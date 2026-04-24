import {type Context, Hono} from "hono";
import {setCookie, deleteCookie} from "hono/cookie"
import type {DBAdapter} from "../db/adapter.js";
import type {Config, hashVersions} from "../config.js";
import {BusinessError, InfrastructureError} from "../errors/types.js";
import z from "zod"
import type {PasswordManager} from "../crypto/password.js";
import type {JWTPayload, TokenManager} from "../crypto/token.js";

/**
 * API router class that extends Hono to provide specialized endpoints for user secrets.
 * It integrates a DBAdapter instance for data persistence and a Config object for environment settings.
 * * To add a new route:
 * 1. Define a new async method to handle the request.
 * 2. Register the method in the setupRoutes() function using Hono routing methods.
 */
export class Api extends Hono{
    DBApi: DBAdapter;
    GlobalConfig: Config;
    PasswordApi: PasswordManager;
    TokenApi: TokenManager;

    /**
     * Initializes the API with required database and configuration dependencies, then sets up internal routing.
     */
    constructor(DBApi: DBAdapter, GlobalConfig: Config, PasswordApi: PasswordManager, TokenApi: TokenManager) {
        super();
        this.DBApi = DBApi;
        this.GlobalConfig = GlobalConfig;
        this.PasswordApi = PasswordApi;
        this.TokenApi = TokenApi;
        this.setupRoutes();
    }

    /**
     * Registers specific HTTP methods and paths to their corresponding internal handler functions.
     */
    setupRoutes(){
        this.post("/register", (c) => this.register(c))
        this.post("/authenticate", (c) => this.authenticate(c))
        this.post("/user/logout", (c) => this.logOut(c))
        this.get("/user", (c) => this.echoToken(c))
    }


    async echoToken(c: Context){
        const jwt = c.get("jwt") as string | undefined;
        const userData = c.get("userData") as JWTPayload | undefined;
        if (jwt && userData) return c.json({jwt, userData}, 200);
        else throw new InfrastructureError("Auth middleware failed", 500)
    }

    async logOut(c: Context){
        deleteCookie(c, 'jwt');
        return c.text("Logged out successfully", 200)
    }


    /**
     * Registers user
     */
    async register(c: Context){
        const registrationFormSchema = z.object({
            password: z.string().max(255).min(8),
            username: z.string().max(255).min(3),
            email: z.email()
        })
        const form = await c.req.json()

        const validationResult = registrationFormSchema.safeParse(form)
        if (!validationResult.success) throw new BusinessError("Bad credentials", 400)

        const data = validationResult.data

        const userDataRequest = await this.DBApi.getUser(data.username, data.email);
        if (userDataRequest.success) throw new BusinessError("User already exists", 401)
        if (userDataRequest.reason !== "User doesn't exist") throw new BusinessError(userDataRequest.reason, 401)

        const salt = this.PasswordApi.generateSalt();

        const passwordHash = await this.PasswordApi.hashPassword(data.password, salt);

        const registrationResult = await this.DBApi.registerUser(data.username, data.email, passwordHash, salt, this.GlobalConfig.crypto.currentVersion)


        if (!registrationResult.success) throw new InfrastructureError("DB error", 507)
        const jwt = this.TokenApi.generateJWT(registrationResult.data.uuid, data.email, data.username)
        setCookie(c, "jwt", jwt)
        return c.text(jwt, 200)
    }


    async authenticate(c: Context){
        const loginFormSchema = z.object({
            password: z.string().max(255).min(8),
            username: z.string().max(255).min(3),
            email: z.email()
        })
        const form = await c.req.json()

        const validationResult = loginFormSchema.safeParse(form)

        if (!validationResult.success) throw new BusinessError("Bad credentials", 400)

        const inputUserData = validationResult.data
        const dbRequest = await this.DBApi.getUser(inputUserData.username, inputUserData.email);

        if (!dbRequest.success) throw new BusinessError("Invalid credentials", 400)

        const dbUserData = dbRequest.data;

        const passwordCheck =  await this.PasswordApi.verifyPassword(inputUserData.password, dbUserData.salt, dbUserData.password_hash, dbUserData.hash_version as hashVersions)

        if (!passwordCheck) throw new BusinessError("Invalid credentials", 400)
        const jwt = this.TokenApi.generateJWT(dbUserData.uuid, dbUserData.email, dbUserData.username);
        setCookie(c, "jwt", jwt)
        return c.text(jwt, 200)
    }
}

export default {Api}