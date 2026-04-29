import {type Config} from "../config.js";

type ESMRecord = {
    value: string;
    timeoutId: ReturnType<typeof setTimeout>;
};

export class ExchangeStorageManager {
    private cache: Map<string, ESMRecord> = new Map();
    private readonly ttlMs: number;
    config: Config;
    constructor(config: Config) {
        this.config = config;
        this.ttlMs = config.crypto.exchangeTTL * 1000;
    }

    public set(key: string, value: string): void {
        const existing = this.cache.get(key);
        if (existing) {
            clearTimeout(existing.timeoutId);
        }

        const timeoutId = setTimeout(() => {
            this.cache.delete(key);
        }, this.ttlMs);

        if (timeoutId.unref) timeoutId.unref();
        this.cache.set(key, { value, timeoutId });
    }

    public pop(key: string): string | undefined {
        const record = this.cache.get(key);

        if (!record) {
            return undefined;
        }
        clearTimeout(record.timeoutId);
        this.cache.delete(key);

        return record.value;
    }
}