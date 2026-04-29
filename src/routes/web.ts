import {type Context, Hono} from "hono";
import {existsSync} from "node:fs";
import {resolve} from "node:path";
import {serveStatic} from "@hono/node-server/serve-static";
import type {Config} from "../config.js";
import z from "zod"
import {BusinessError} from "../errors/types.js";
import {setCookie} from "hono/cookie";
/**
 * Web router class that extends Hono to serve static assets from a configured directory.
 * It validates the existence of the target path before mounting the static middleware.
 */
export class Web extends Hono {

    /**
     * Initializes the static file server. Requires a global configuration object containing the base path for web assets.
     */
    constructor(GlobalConfig: Config) {
        super();

        const absolutePath = resolve(GlobalConfig.webPath);

        if (!existsSync(absolutePath)) {
            throw new Error(`webPath ${GlobalConfig.webPath} doesn't exist`);
        }
        this.use("/*", serveStatic({ root: GlobalConfig.webPath }));
        this.setupRoutes();
    }

    setupRoutes(){
        this.get("/authenticate", (c) => this.authenticate(c));
    }



    authenticate(c: Context){
        const form = c.req.query();
        const contextParameters = z.object({
            redirect_url: z.url(),
            auditor: z.string(),
        })


        const validationResult = contextParameters.safeParse(form);

        if (!validationResult.success) throw new BusinessError("Bad request", 400);

        const context = validationResult.data;

        console.log(context)

        setCookie(c, "auditor", context.auditor);
        setCookie(c, "redirect_url", context.redirect_url);

        return c.redirect("/index.html", 303);

    }


}

export default {Web}