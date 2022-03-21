const express = require("express");
const bodyParser = require("body-parser");
const {
    createProxyMiddleware
} = require('http-proxy-middleware');
const cors = require('cors');
const log4js = require("log4js");

const {
    Err,
    Env,
    Sleep,
    Reply,
    checkDependencies
} = require("./utils.js");

const {DataBase} = require("./db.js");

const {Auth} = require("./auth.js");

// Server Configurations
const IMG_TAG = Env("IMG_TAG");

const SERVER_PORT = Number(Env("SERVER_PORT", 80));
const WHITELIST_FILE = Env("WHITELIST_FILE", '/login-api/whitelist.txt');
const RESET_WHITELIST = Env("RESET_WHITELIST", 'false') == 'true';

const BACKEND_URL = Env("BACKEND_URL");
const N_CONNECTION_TRIES = Number(Env("N_CONNECTION_TRIES", 10));
const SLEEP_CONNECTION_TRIES = Number(Env("SLEEP_CONNECTION_TRIES", 1000));

const JWT_SECRET = Env("JWT_SECRET");
const JWT_DURATION = Number(Env("JWT_DURATION", 1800));

const POSTGRES_HOST = Env("POSTGRES_HOST");
const POSTGRES_DB = Env("POSTGRES_DB");
const POSTGRES_USER = Env("POSTGRES_USER");
const POSTGRES_PASSWORD = Env("POSTGRES_PASSWORD");
const POSTGRES_PORT = Number(Env("POSTGRES_PORT"));

// Configure Logger
log4js.configure({
    appenders: {
        out: {
            type: 'stdout',
            layout: {
                type: 'pattern',
                pattern: '%[[%d{dd-MM-yyyy hh:mm:ss}] %p ::%] %m',
            }
        }
    },
    categories: {
        default: {
            appenders: ['out'],
            level: 'debug'
        }
    }
});
const log = log4js.getLogger("main");

// Configure DataBase
const db = new DataBase({
    host: POSTGRES_HOST,
    database: POSTGRES_DB,
    user: POSTGRES_USER,
    password: POSTGRES_PASSWORD,
    port: POSTGRES_PORT,
});

const auth = new Auth(JWT_SECRET, JWT_DURATION, db);

// Configure Express
const server = express();

server.use(bodyParser.urlencoded({
    extended: false
}));

server.use(bodyParser.json());

server.use(cors({
    origin: '*'
}));

// API Endpoints

const login_resource = express.Router();

login_resource.get('/', (req, res) => {
    // Retrieve and send current monotonic timestamp
    res.json(auth.getNonce());
});

login_resource.post('/', async (req, res) => {
    // Retrieve Parameters
    let {
        address,
        signature,
        timestamp
    } = req.body ?? {};

    // Login
    let reply = await auth.login(address, signature, timestamp);

    // Send Response
    res.status(reply.status).json(reply.body);

    // Log
    let str = (reply.status == 200 ? "" : " : " + reply.body);
    log.debug(`LOGIN ${address} -> ${res.statusCode} ${res.statusMessage}${str}`);
});

// Register the login resource
server.use("/login", login_resource);

// Enforce authorization verification of every non-login request
server.use('', (req, res, next) => {
    // Retrieve token from request headers
    const token = req.headers['x-access-token'] ?? req.headers['authorization']?.split(' ')[1];

    // Verify token
    let reply = auth.verifyAuthToken(token);

    if (reply.status == 200)
        next();
    else
        res.status(reply.status).send(reply.body);
});

// Proxy Requests
server.use('/', createProxyMiddleware({
    target: BACKEND_URL,
    changeOrigin: false,
    ws: true,
    //logLevel: 'debug',
    /*pathRewrite: {
        [`^/json_placeholder`]: '',
    },*/
}));

async function main() {
    log.debug(`crypto-login ${IMG_TAG}`);

    // Wait for the dependencies to initialize
    const dependencies = [
        `${POSTGRES_HOST}:${POSTGRES_PORT}`,
        BACKEND_URL //.replace(/http[s]?:\/\//, "")
    ];
    await checkDependencies(dependencies, N_CONNECTION_TRIES, SLEEP_CONNECTION_TRIES);

    // Initialize the database
    await db.init(RESET_WHITELIST, WHITELIST_FILE);

    // Start the web server
    /*const sv = */
    await server.listen(SERVER_PORT);

    log.debug(`Listening on TCP/${SERVER_PORT} ...\n`);
}
main();
