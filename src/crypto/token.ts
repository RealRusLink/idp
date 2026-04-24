import {Config} from "../config.js";
import {createHash, createSign, createVerify, publicDecrypt, type RsaPublicKey, sign} from "node:crypto";
import z from "zod";

export interface JWTPayload {sub: string, username: string, email: string, exp: number, iat: number}

export type verifyJWTfeedback =
    | { success: false, reason: "Bad JWT format" | "Compromised JWT" | "Expired" }
    | { success: true, payload: JWTPayload };

const JWTPayloadSchema = z.object({
    sub: z.string(),
    username: z.string(),
    email: z.string().email(),
    exp: z.number(),
    iat: z.number()
});

export class TokenManager {
    config: Config;
    constructor(GlobalConfig: Config) {
        this.config = GlobalConfig;
    }

    generateJWT(uuid: string, email: string, username: string){
        const header = {
            "alg": "RS256",
            "typ": "JWT"
        }

        const payload = {
            sub: uuid,
            username: username,
            email: email,
            exp: Math.floor((Date.now() + this.config.crypto.jwtTTL)/1000),
            iat: Math.floor(Date.now()/1000),
        }

        const section = Buffer.from(JSON.stringify(header)).toString("base64url") + "." + Buffer.from(JSON.stringify(payload)).toString("base64url");

        const signer = createSign("RSA-SHA256");
        signer.update(section);
        const signature = signer.sign(this.config.crypto.key.private).toString("base64url")
        return `${section}.${signature}`
    };



    verifyJWT(jwt: string, publicKey: string = this.config.crypto.key.public): verifyJWTfeedback {
        const parts = jwt.split('.');
        if (parts.length !== 3) return { success: false, reason: "Bad JWT format" };

        const [encodedHeader, encodedPayload, encodedSignature] = parts;

        // 1. Криптографическая проверка (Всегда первая!)
        const verifier = createVerify("RSA-SHA256");
        verifier.update(`${encodedHeader}.${encodedPayload}`);

        const isSignatureValid = verifier.verify(
            publicKey,
            encodedSignature || "",
            "base64url"
        );
        if (!isSignatureValid) return { success: false, reason: "Compromised JWT" };
        let rawPayload: any;
        try {
            rawPayload = JSON.parse(Buffer.from(encodedPayload || "", "base64url").toString());
        } catch {
            return { success: false, reason: "Bad JWT format" };
        }
        const result = JWTPayloadSchema.safeParse(rawPayload);
        if (!result.success) return { success: false, reason: "Bad JWT format" };
        if (result.data.exp < Math.floor(Date.now() / 1000)) {
            return { success: false, reason: "Expired" };
        }

        return { success: true, payload: result.data };
    }


}
