import {type Context, type MiddlewareHandler, type Next} from "hono";
import  { getCookie } from "hono/cookie"
import {type LoggerService} from "logger/dist/index.js"
import {AppError, BusinessError} from "../errors/types.js";
import type {TokenManager} from "../crypto/token.js";

/**
 * Base abstract class for creating Hono middleware.
 * Exposes a standardized handler that bridges Hono's middleware interface with the internal execute logic.
 * * To implement custom middleware:
 * 1. Extend this class.
 * 2. Implement the protected `execute` method with your logic.
 * 3. Call `await next()` within `execute` to continue the request lifecycle.
 */
export abstract class Middleware{

    /**
     * The middleware handler function to be registered in Hono.
     */
    public readonly handler: MiddlewareHandler = (c, next) => this.execute(c, next);

    /**
     * Internal logic of the middleware to be implemented by subclasses.
     */
    abstract execute: (c: Context, next: Next) => Promise<Response | void>

}



/**
 * Middleware implementation that logs the lifecycle of an HTTP request, including method, path, and execution duration.
 * Requires a LoggerService instance for output.
 */
export class LoggerMiddleware extends Middleware{
    logger: LoggerService;
    constructor(Logger: LoggerService) {
        super();
        this.logger = Logger;
    }

    /**
     * Records the start of the request, awaits execution, and logs the total processing time.
     */
    execute = async (c: Context, next: () => Promise<void>) => {
        this.logger.info(`Entered endpoint ${c.req.method} ${c.req.path}`);
        const time = performance.now();
        await next();
        this.logger.info(`Endpoint ${c.req.method} ${c.req.path} finished in ${performance.now() - time} ms`)
    }


}



/**
 * Middleware implementation that handles authentication concerns.
 * Requires a TokenManager instance for validation.
 */
export class AuthenticationMiddleware extends Middleware{
    TokenApi: TokenManager;
    constructor(TokenApi: TokenManager) {
        super();
        this.TokenApi = TokenApi;
    }

    /**
     * Checks if JWT is present and valid.
     */
    execute = async (c: Context, next: () => Promise<void>) => {
        const token = getCookie(c, "jwt");
        if (!token) throw new BusinessError("No JWT", 401);
        const tokenCheck = this.TokenApi.verifyJWT(token);
        if (!tokenCheck.success) throw new BusinessError(tokenCheck.reason, 401);
        c.set("jwt", token);
        c.set("userData", tokenCheck.payload)
        await next()
    }


}

/**
 * Global error handling function that catches exceptions, distinguishing between known AppErrors and unexpected internal errors.
 */
export function errorHandler (err: Error, c: Context){
    if (err instanceof AppError) return c.text(err.customMessage, err.code)
    return c.text("Unknown error", 500)
}