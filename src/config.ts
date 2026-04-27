import dotenv from "dotenv";
import { generateKeyPairSync } from "node:crypto";

export type hashVersions = "default";

interface ConfigIF {
    webPath: string;
    listenPort: number;
    db: {
        host: string;
        port: number;
        name: string;
        user: string;
        password: string;
        tables: {
            users: string;
            refreshTokens: string;
        };
    };
    issuer: string;
    crypto: {
        currentVersion: hashVersions;
        default: {
            iterations: number;
            keyLength: number;
            digest: string;
            saltLength: number;
        };
        jwtTTL: number;
        refreshTTL: number;
        refreshTimeout: number;
        key: {
            private: string;
            public: string;
            updated: number;
        };
    };
}

export class Config implements ConfigIF {
    public webPath: string;
    public listenPort: number;
    public db: ConfigIF["db"];
    public issuer: string;
    public crypto: ConfigIF["crypto"];

    constructor() {
        dotenv.config({ quiet: true });

        this.webPath = process.env.WEB_PATH || "";
        this.listenPort = Number(process.env.LISTEN_PORT || 80);
        this.db = {
            host: process.env.DB_HOST || "",
            port: Number(process.env.DB_PORT || 0),
            name: process.env.DB_NAME || "",
            user: process.env.DB_USER || "",
            password: process.env.DB_PASSWORD || "",
            tables: {
                users: process.env.USERS_TABLE || "",
                refreshTokens: process.env.REFRESH_TABLE || "",
            }
        };
        this.issuer = process.env.ISSUER || "",
        this.crypto = {
            currentVersion: (process.env.CURRENT_HASH_VERSION as hashVersions) || "default",
            default: {
                iterations: Number(process.env.HASH_ITERATIONS_default),
                keyLength: Number(process.env.HASH_KEY_LENGTH_default),
                digest: process.env.HASH_DIGEST_default || "",
                saltLength: Number(process.env.HASH_SALT_LENGTH_default)
            },
            jwtTTL: Number(process.env.JWT_TTL),
            refreshTTL: Number(process.env.REFRESH_TTL),
            refreshTimeout: Number(process.env.REFRESH_TIMEOUT),
            key: {
                private: "",
                public: "",
                updated: 0
            }
        };
        this.generateKeys();
        this.checkConfig(this, "GLOBAL_CONFIG");
    }

    private generateKeys(): void {
        const { publicKey, privateKey } = generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });

        this.crypto.key = {
            private: privateKey,
            public: publicKey,
            updated: Date.now()
        };
    }

    public checkConfig(obj: Record<string, any>, objName: string): void {
        for (const key in obj) {
            const val = obj[key];
            if (val === undefined || val === null || (typeof val === "number" && Number.isNaN(val)) || val === "") {
                throw new Error(`${objName}.${key} is invalid (${val}). Config failed to load.`);
            }
            if (typeof val === "object" && !Array.isArray(val)) {
                this.checkConfig(val, `${objName}.${key}`);
            }
        }
    }
}

export default { Config };