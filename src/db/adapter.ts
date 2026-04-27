import {type DBConnector} from "./config.js";
import {type Config, type hashVersions} from "../config.js";

/**
 * Feedback types representing structured response objects returned by database operations to indicate success or specific error reasons.
 */
export type User = {
    uuid: string,
    username: string,
    email: string,
    password_hash: string,
    salt: string,
    is_active: string,
    hash_version: string,
    creation_date: string,
    update_date: string,
}


export type getUserFeedback =
    | { success: true, data: User }
    | { success: false, reason: "User doesn't exist" | "DB failure" | "Both username and email are already taken" | "Username is already taken" | "Email is already taken"}

export type tokenFeedback = {success: true, uuid: string} | {success: false}

/**
 * Data access layer that provides methods for user management and secret handling.
 * Requires an instance of DBConnector (holding the connection pool) and a Config object for table mapping.
 */
export class DBAdapter {
    connection: DBConnector;
    config: Config;

    /**
     * Initializes the adapter with a database connection pool and global configuration.
     */
    constructor(DBConnection: DBConnector, GlobalConfig: Config) {
        this.connection = DBConnection;
        this.config = GlobalConfig
    }




    async doesUserExist(username: string, email: string): Promise<boolean> {
        const queryResult = await this.connection.pool.query(
            `SELECT username FROM ${this.config.db.tables.users} WHERE username = $1 AND email = $2`,
            [username, email]
        );
        return queryResult.rows.length !== 0;
    }


    async registerUser(username: string, email: string, passwordHash: string, salt: string, hashVersion: hashVersions): Promise<getUserFeedback>{
        const queryResult = await  this.connection.pool.query(
            `INSERT INTO 
            ${this.config.db.tables.users} (username, email, password_hash, salt, hash_version)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *`,
            [username, email, passwordHash, salt, hashVersion]
        )
        return queryResult.rows.length > 0 ? {success: true, data: queryResult.rows[0]} : {success: false, reason: "DB failure"};
    }

    async getUserById(uuid: string):Promise<getUserFeedback>{
        const queryResult = await  this.connection.pool.query(`
        SELECT * FROM ${this.config.db.tables.users} WHERE uuid = $1`, [uuid]
        )
        return queryResult.rows.length > 0 ? {success: true, data: queryResult.rows[0] as User} : {success: false, reason: "User doesn't exist"}
    }


    async getUser(username: string, email: string): Promise<getUserFeedback> {
        const queryResult = await this.connection.pool.query(
            `SELECT * FROM ${this.config.db.tables.users} 
         WHERE username = $1 OR email = $2`,
            [username, email]
        );

        if (queryResult.rows.length > 0) {
            const existingUser = queryResult.rows[0];

            if (existingUser.username === username && existingUser.email === email) {
                return { success: true, data: existingUser };
            } else if (queryResult.rows.length > 1){
                return { success: false, reason: "Both username and email are already taken" };
            } else if (existingUser.username === username) {
                return { success: false, reason: "Username is already taken" };
            } else {
                return { success: false, reason: "Email is already taken" };
            }
        }

        return { success: false, reason: "User doesn't exist" };
    }



    async writeTokenHash(uuid: string, tokenHash: string, expire: number = this.config.crypto.refreshTTL){
        const queryResult = await this.connection.pool.query(
            `INSERT INTO ${this.config.db.tables.refreshTokens} (token_hash, user_id, exp)
            VALUES ($1, $2, $3)
            RETURNING exp`, [tokenHash, uuid, new Date(Date.now() + expire)]
        )
        return queryResult.rows[0].exp as Date
    }

    async deleteTokenHash(tokenHash: string){
        const queryResult = await this.connection.pool.query(`DELETE FROM ${this.config.db.tables.refreshTokens} 
        WHERE token_hash = $1`, [tokenHash]);
        return queryResult.rows.length > 0;
    }


    async verifyTokenHash(tokenHash: string): Promise<tokenFeedback>{
        const queryResult = await this.connection.pool.query(`
            SELECT user_id FROM ${this.config.db.tables.refreshTokens} WHERE token_hash = $1 AND exp > NOW()`,
            [tokenHash])
        return queryResult.rows.length > 0 ? {success: true, uuid: queryResult.rows[0].user_id} : {success: false}
    }


}

export default {DBAdapter}