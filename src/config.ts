import dotenv from "dotenv";
import { generateKeyPairSync } from "node:crypto";

export type hashVersions = "default";

const loadData = () => {
    dotenv.config({ quiet: true });
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    return {
        webPath: process.env.WEB_PATH || "",
        listenPort: Number(process.env.LISTEN_PORT || 80),
        issuer: process.env.ISSUER || "",
        db: {
            host: process.env.DB_HOST || "",
            port: Number(process.env.DB_PORT || 0),
            name: process.env.DB_NAME || "",
            user: process.env.DB_USER || "",
            password: process.env.DB_PASSWORD || "",
            tables: {
                users: process.env.USERS_TABLE || "",
                refreshTokens: process.env.REFRESH_TABLE || "",
            }
        },
        crypto: {
            currentVersion: (process.env.CURRENT_HASH_VERSION as hashVersions) || "default",
            default: {
                iterations: Number(process.env.HASH_ITERATIONS_default),
                keyLength: Number(process.env.HASH_KEY_LENGTH_default),
                digest: process.env.HASH_DIGEST_default || "",
                saltLength: Number(process.env.HASH_SALT_LENGTH_default)
            },
            jwtTTL: Number(process.env.JWT_TTL),
            refreshTTL: Number(process.env.REFRESH_TTL),
            exchangeTTL: Number(process.env.EXCHANGE_TTL),
            refreshTimeout: Number(process.env.REFRESH_TIMEOUT),
            key: {
                private: privateKey,
                public: publicKey,
                updated: Date.now()
            }
        }
    };
};

type ConfigData = ReturnType<typeof loadData>;

abstract class ConfigBase {}
interface ConfigBase extends ConfigData {}

export class Config extends ConfigBase {
    constructor() {
        super();

        const data = loadData();
        this.checkConfig(data, "GLOBAL_CONFIG");
        Object.assign(this, data);
    }

    private checkConfig(obj: Record<string, any>, objName: string): void {
        for (const key in obj) {
            const val = obj[key];

            if (val === undefined || val === null || val === "" || (typeof val === "number" && Number.isNaN(val))) {
                throw new Error(`${objName}.${key} is invalid (${val}). Config failed to load.`);
            }
            if (typeof val === "object" && !Array.isArray(val)) {
                this.checkConfig(val, `${objName}.${key}`);
            }
        }
    }
}

export default { Config };