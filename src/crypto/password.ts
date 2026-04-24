import { randomBytes, pbkdf2 } from 'node:crypto';
import { promisify } from 'node:util';
import type {Config, hashVersions} from "../config.js";


const pbkdf2Async = promisify(pbkdf2);

export class PasswordManager {

    config: Config

    constructor(GlobalConfig: Config) {
        this.config = GlobalConfig;
    }

    generateSalt(): string {
        return randomBytes(16).toString('hex');
    }

    async hashPassword(password: string, salt: string, version: hashVersions = this.config.crypto.currentVersion): Promise<string> {

        const hash = await pbkdf2Async(
            password,
            salt,
            this.config.crypto[version].iterations,
            this.config.crypto[version].keyLength,
            this.config.crypto[version].digest
        );
        return hash.toString('hex');
    }

    async verifyPassword(password: string, salt: string, storedHash: string, version: hashVersions = this.config.crypto.currentVersion): Promise<boolean> {
        const targetHash = await this.hashPassword(password, salt, version);
        return targetHash === storedHash;
    }
}