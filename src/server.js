"use strict";

const pg = require("pg");
const Path = require("path");
var moment = require("moment-timezone");
const log = require("./util/log");
const Hapi = require("@hapi/hapi");
const Constant = require("./util/constant");
const Helper = require("./util/helper");
// const _ = require("underscore");

require("dotenv").config({ path: `./src/env/.env.${process.env.NODE_ENV}` });

let server;

const init_db = () => {

    const pool = new pg.Pool({
        user: process.env.DB_USER,
        host: process.env.DB_HOST,
        database: process.env.DB_NAME,
        password: process.env.DB_PASSWORD,
        port: process.env.DB_PORT,
        max: 20, // set pool max size to 20
        idleTimeoutMillis: 30000, // close idle clients after 30 second
        connectionTimeoutMillis: 2000, // return an error after 2 second if connection could not be established
        maxUses: 7500, // close (and replace) a connection after it has been used 7500 times (see below for discussion)
    });
    return pool;
};

const start_server = async () => {
    const pool = init_db();
    server = Hapi.server({
        port: process.env.APP_PORT || 3000,
        host: process.env.APP_HOST || "localhost",
        routes: {
            cors: {
                origin: ["*"],
            },
        },
    });

    await server.register(require("hapi-auth-jwt2"));
    await server.auth.strategy("jwt", "jwt", {
        complete: true,
        tokenType: Constant.BEARER,
        key: process.env.ACCESS_TOKEN_SECRET,
        verifyOptions: { ignoreExpiration: false, algorithms: [Constant.ALGORITHM] },
        validate: async (decoded, request, h) => {
            let user = await Helper.get_access_token_from_db(request);
            if (user == null) {
                return { isValid: false, errorMessage: "Invalid token" };
            }
            if (user["status"] != "signin") {
                return { isValid: false, errorMessage: "Already signout" };
            }

            let sign_out_time = moment(user["sign_out_time"], "YYYY-MM-DD HH:mm:ss.SSS").tz("Asia/Dhaka");
            if (sign_out_time.isBefore(moment())) {
                return { isValid: false, errorMessage: "Token expired" };
            }
            return { isValid: true, credentials: decoded };
        },
    });

    await server.register({
        plugin: require("hapi-auto-route"),
        options: {
            routes_dir: Path.join(__dirname, "routes"),
        },
    });

    await server.register({
        plugin: require("hapi-authorization"),
        options: {
            roles: false,
        },
    });

    await server.register({
        plugin: require("blipp"),
        options: {
            showAuth: true,
        },
    });

    server.ext("onRequest", function (request, h) {
        request.headers["request-time"] = moment().valueOf();
        return h.continue;
    });

    server.ext("onPreAuth", async (request, h) => {
        request.pg = pool;
        return h.continue;
    });

    server.events.on("start", () => {
        pool.connect().then((err, client, release) => log.info(`Postgres connected`));
        pool.on("error", (err) => {
            log.error(`Postgres bad has happened!`, err.stack);
        });
        log.info(`Hapi js(${server.version}) running on ${server.info.uri}`);
    });

    await server.start();
};

process.on("unhandledRejection", (err) => {
    log.error(err);
    process.exit(1);
});

start_server();