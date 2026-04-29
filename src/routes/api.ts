import {type Context, Hono} from "hono";
import {setCookie, deleteCookie, getCookie} from "hono/cookie"
import type {DBAdapter, User} from "../db/adapter.js";
import type {Config, hashVersions} from "../config.js";
import {BusinessError, InfrastructureError} from "../errors/types.js";
import z from "zod"
import type {PasswordManager} from "../crypto/password.js";
import type {JWTPayload, TokenManager} from "../crypto/token.js";
import type {ExchangeStorageManager} from "../db/exchange.js";

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
    ExchangeApi: ExchangeStorageManager;
    /**
     * Initializes the API with required database and configuration dependencies, then sets up internal routing.
     */
    constructor(DBApi: DBAdapter, GlobalConfig: Config, PasswordApi: PasswordManager, TokenApi: TokenManager, ExchangeApi: ExchangeStorageManager) {
        super();
        this.DBApi = DBApi;
        this.GlobalConfig = GlobalConfig;
        this.PasswordApi = PasswordApi;
        this.TokenApi = TokenApi;
        this.ExchangeApi = ExchangeApi;
        this.setupRoutes();
    }

    /**
     * Registers specific HTTP methods and paths to their corresponding internal handler functions.
     */
    setupRoutes(){
        this.post("/register", (c) => this.register(c))
        this.post("/login", (c) => this.login(c))
        this.post("/rotate", (c) => this.rotation(c))
        this.post("/exchange", (c) => this.exchange(c))
        this.all("/user/logout", (c) => this.logOut(c))
        this.post("/user/removejwt", (c) => this.removeJWT(c))
        this.get("/user", (c) => this.echoToken(c))
        this.get("/key", (c) => this.getKey(c))
    }


    async echoToken(c: Context){
        const jwt = c.get("jwt") as string | undefined;
        const userData = c.get("userData") as JWTPayload | undefined;
        if (jwt && userData) return c.json({jwt, userData}, 200);
        else throw new InfrastructureError("Auth middleware failed", 500)
    }

    async logOut(c: Context) {
        const redirectUrl = getCookie(c, "return_to") || c.req.query("return_to");
        deleteCookie(c, 'jwt', { path: '/' });
        deleteCookie(c, 'refresh', { path: '/' });
        deleteCookie(c, "redirect_url", { path: '/' });
        deleteCookie(c, "auditor", { path: '/' });

        if (redirectUrl) {
            try {
                const validUrl = new URL(redirectUrl);
                return c.redirect(validUrl.toString(), 303);
            } catch (e) {
                return c.redirect('/', 303);
            }
        }

        return c.text("Logged out successfully", 200);
    }

    async removeJWT(c: Context){
        deleteCookie(c, 'jwt');
        return c.text("Removed JWT successfully", 200)
    }


    async verifyUserCredentials(credentials: object){
        const credentialsFormSchema = z.object({
            password: z.string().max(255).min(8),
            username: z.string().max(255).min(3),
            email: z.email()
        });
        const validationResult = credentialsFormSchema.safeParse(credentials)
        if (!validationResult.success) throw new BusinessError("Bad credentials", 400)
        return validationResult.data;
    }



    async handleRedirection(c: Context, savedUserData: User) {
        const redirect_url = getCookie(c, "redirect_url");
        const auditor = getCookie(c, "auditor");

        const contextParameters = z.object({
            redirect_url: z.string().url(),
            auditor: z.string(),
        });

        const contextValidationResult = contextParameters.safeParse({ redirect_url, auditor });

        deleteCookie(c, "redirect_url");
        deleteCookie(c, "auditor");

        if (contextValidationResult.success) {
            const foreignJWT = this.TokenApi.generateJWT(
                savedUserData.uuid,
                savedUserData.email,
                savedUserData.username,
                contextValidationResult.data.auditor
            );

            const fullRedirect = new URL(contextValidationResult.data.redirect_url);
            const code = this.TokenApi.generateExchange();

            this.ExchangeApi.set(code, foreignJWT);

            fullRedirect.searchParams.set("code", code);
            fullRedirect.protocol = "http";

            return {
                type: "external",
                url: fullRedirect.toString()
            };
        }

        return {
            type: "internal",
            url: "/profile.html"
        };
    }

    async register(c: Context) {
        const userShouldNotExist = async (username: string, email: string) => {
            const userDataRequest = await this.DBApi.getUser(username, email);
            if (userDataRequest.success) throw new BusinessError("User already exists", 401);
        };

        const saveUser = async (username: string, email: string, password: string) => {
            const salt = this.PasswordApi.generateSalt();
            const passwordHash = await this.PasswordApi.hashPassword(password, salt);
            const registrationResult = await this.DBApi.registerUser(username, email, passwordHash, salt, this.GlobalConfig.crypto.currentVersion);
            if (!registrationResult.success) throw new InfrastructureError("DB error", 507);
            return registrationResult.data;
        };

        const registrationData = await this.verifyUserCredentials(await c.req.json());
        await userShouldNotExist(registrationData.username, registrationData.email);

        const savedUserData = await saveUser(registrationData.username, registrationData.email, registrationData.password);

        const jwt = this.TokenApi.generateJWT(savedUserData.uuid, savedUserData.email, savedUserData.username);
        setCookie(c, "jwt", jwt);
        setCookie(c, "refresh", await this.#createRefresh(savedUserData.uuid));

        const redirection = await this.handleRedirection(c, savedUserData);

        return c.json({
            success: true,
            message: "Registration successful",
            jwt: jwt,
            ...redirection
        }, 200);
    }

    async login(c: Context) {
        const form = await c.req.json();

        const getUser = async (username: string, email: string) => {
            const dbRequest = await this.DBApi.getUser(username, email);
            if (!dbRequest.success) throw new BusinessError("Invalid credentials", 400);
            return dbRequest.data;
        };

        const inputUserData = await this.verifyUserCredentials(form);
        const userData = await getUser(inputUserData.username, inputUserData.email);

        const passwordCheck = await this.PasswordApi.verifyPassword(
            inputUserData.password,
            userData.salt,
            userData.password_hash,
            userData.hash_version as hashVersions
        );

        if (!passwordCheck) throw new BusinessError("Invalid credentials", 400);

        const jwt = this.TokenApi.generateJWT(userData.uuid, userData.email, userData.username);
        setCookie(c, "jwt", jwt);
        setCookie(c, "refresh", await this.#createRefresh(userData.uuid));

        const redirection = await this.handleRedirection(c, userData);

        return c.json({
            success: true,
            message: "Login successful",
            jwt: jwt,
            ...redirection
        }, 200);
    }


    async rotation(c: Context) {
        const validationFormSchema = z.string().max(255)
        const form = getCookie(c,"refresh");
        if (!form) throw new BusinessError("Unauthorised", 401);
        const validationResult = validationFormSchema.safeParse(form);
        if (!validationResult.success) throw new BusinessError("Bad token", 400)
        const userTokenHash  = this.TokenApi.hashRefresh(validationResult.data);
        const tokenCheckResult = await this.DBApi.verifyTokenHash(userTokenHash);
        if (!tokenCheckResult.success) throw new BusinessError("Unauthorised", 401);

        const newRefreshToken = await this.#createRefresh(tokenCheckResult.uuid);

        await this.DBApi.deleteTokenHash(userTokenHash);

        const userDataRequest = await this.DBApi.getUserById(tokenCheckResult.uuid);

        if (!userDataRequest.success) throw new InfrastructureError(userDataRequest.reason, 507);


        const jwt = this.TokenApi.generateJWT(userDataRequest.data.uuid, userDataRequest.data.email, userDataRequest.data.username)
        setCookie(c, "jwt", jwt)
        setCookie(c, "refresh", newRefreshToken);
        return c.text(jwt + newRefreshToken, 200)

    }


    async exchange(c: Context){
        const form = await c.req.json()
        const codeValidationForm = z.object({
            code: z.string()
        })

        const validationResult = codeValidationForm.safeParse(form);

        if (!validationResult.success) throw new BusinessError("Bad request", 400);

        const getJWT = this.ExchangeApi.pop(validationResult.data.code);

        if (!getJWT) throw new BusinessError("Unauthorised", 401);

        return c.text(getJWT, 200);

    }


    async getKey(c: Context){
        return c.text(this.GlobalConfig.crypto.key.public, 200);
    }




    async #createRefresh(uuid: string){
        const token = this.TokenApi.generateRefresh();
        const tokenHash = this.TokenApi.hashRefresh(token);
        await this.DBApi.writeTokenHash(uuid, tokenHash, this.GlobalConfig.crypto.refreshTTL);
        return token;
    }


}

export default {Api}