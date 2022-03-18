const express = require("express");
const bodyParser = require("body-parser");
const clock = require('monotonic-timestamp');
const jwt = require('jsonwebtoken');
const {
    signatureVerify
} = require('@polkadot/util-crypto');
const {
    hexToU8a
} = require('@polkadot/util');
const pg = require('pg');
const fs = require('fs/promises');
const net = require('net-promise');
//const readline = require('readline');
const csv = require('csv-parser');
const {
    createProxyMiddleware
} = require('http-proxy-middleware');
const cors = require('cors');
const log4js = require("log4js");

// Auxiliary Utility Functions
const Env = (key, default_value = undefined) => {
    if (process.env[key]) {
        return process.env[key];
    } else {
        if (default_value) {
            return default_value;
        } else {
            throw `Invalid environment variable ${key}`;
        }
    }
}

const Sleep = ms => new Promise(r => setTimeout(r, ms));

const Reply = (status = 200, body = "") => ({
    status: status,
    body: body
});

// Server Configurations
const IMG_TAG = Env("IMG_TAG");

const SERVER_PORT = Number(Env("SERVER_PORT", 80));
const JWT_SECRET = Env("JWT_SECRET");
const JWT_DURATION = Number(Env("JWT_DURATION", 1800));
const WHITELIST_FILE = Env("WHITELIST_FILE", '/login-api/whitelist.txt');
const RESET_WHITELIST = Env("RESET_WHITELIST", 'false') == 'true';

const BACKEND_URL = Env("BACKEND_URL");

const N_CONNECTION_TRIES = Number(Env("N_CONNECTION_TRIES", 10));

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
var log = log4js.getLogger();

// Configure Express
const login_resource = express.Router();
const server = express();
server.use(bodyParser.urlencoded({
    extended: false
}));
server.use(bodyParser.json());
server.use(cors({
    origin: '*'
}));

// Configure DB
const db = new pg.Pool({
    host: POSTGRES_HOST,
    database: POSTGRES_DB,
    user: POSTGRES_USER,
    password: POSTGRES_PASSWORD,
    port: POSTGRES_PORT,
});

// Auxiliary Functions and Variables

async function checkConnection(dep) {
    return new Promise(async (resolve, reject) => {
        var aux = dep.split(":");
        var host = aux[0];
        var port = Number(aux[1] ? aux[1] : "80");

        var connected = false;
        for (var i = 0; i < N_CONNECTION_TRIES && !connected; i++) {
            try {

                var client = await net.Socket({
                    host: host,
                    port: port
                });
                connected = true;
                client.close();

            } catch (err) {
                // Ignore and try again
                await Sleep(1000);

                log.debug(`Re-trying to connect to ${dep} (attempt ${i+1}/${N_CONNECTION_TRIES}) ...`);
            }
        }
        if (N_CONNECTION_TRIES > 0) {
            if (!connected) {
                reject(Error(`Cannot connect to ${dep}`));
            } else {
                log.debug(`Connected to ${dep}`);

                resolve();
            }
        } else {
            resolve();
        }
    });
}

async function onReady(deps) {
    var px = [];

    deps.forEach((dep, i) => {
        var p = checkConnection(dep);
        px.push(p);
    });

    return Promise.all(px);
}

async function fillDB() {

    // Create Table
    var res = await db.query('CREATE TABLE whitelist (address VARCHAR(255) PRIMARY KEY, name VARCHAR(255), enabled BOOLEAN, last_timestamp BIGINT);');

    // Insert Entries
    try {
        await fs.access(WHITELIST_FILE, require('fs').constants.R_OK);

        var fd = await fs.open(WHITELIST_FILE);

        return new Promise(async (resolve, reject) => {
            var px = [];
            var inserted = 0;

            const parseRow = async (raw_row) => {
                console.log(raw_row);

                var address = raw_row.address?.trim();
                var name = String(raw_row.name?.trim());
                var enabled = raw_row.enabled?.trim() == "true";
                var last_timestamp = 0;

                var p = db.query("INSERT INTO whitelist (address, name, enabled, last_timestamp) VALUES ($1, $2, $3, $4);", [address, name, enabled, last_timestamp]);

                px.push(p);
            }

            fd.createReadStream()
                .pipe(csv({
                    separator: ';'
                }))
                .on('data', parseRow)
                .on('end', async () => {
                    var inserted = (await Promise.all(px)).length;
                    resolve(inserted);

                    // console.log("WHITELIST", (await db.query('SELECT * FROM whitelist')).rows);
                });
        });
    } catch (err) {
        log.debug(err);

        process.exit();
    }
}

async function initDB() {

    var table_exists = (await db.query("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name='whitelist');")).rows[0]?.exists;

    if (table_exists) {
        if (RESET_WHITELIST) {
            await db.query('DROP TABLE whitelist;');

            log.debug("Whitelist cleared!");

            var n_inserted = await fillDB();
            log.debug(`Inserted ${n_inserted} entries in whitelist.`);
        } else {
            var n_addresses = (await db.query("SELECT COUNT(address) FROM whitelist;")).rows[0]?.count;

            log.debug(`Whitelist already exists with ${n_addresses} addresses.`);
        }
    } else {
        var n_inserted = await fillDB();
        log.debug(`Inserted ${n_inserted} entries in whitelist.`);
    }
}

async function getLastTimestamp(address) {
    return (await db.query("SELECT last_timestamp FROM whitelist WHERE address=$1 AND enabled='true'", [address])).rows[0]?.last_timestamp;
}

async function setLastTimestamp(address, ts) {
    await db.query('UPDATE whitelist SET last_timestamp = $1 WHERE address = $2', [ts, address]);
}

function verifySignature(address, signature, data) {
    try {
        return signatureVerify(data, hexToU8a(signature), address).isValid;
    } catch (err) {
        return false;
    }
}

function getAuthToken(address) {
    return jwt.sign({
        address: address
    }, JWT_SECRET, {
        expiresIn: `${JWT_DURATION}s`
    });
}

function verifyAuthToken(token) {
    if (!token || token == "") {
        return Reply(401, 'No Token Provided');
    }

    try {
        var decoded = jwt.verify(token, JWT_SECRET);

        // console.log(Date.now(), decoded);

        return Reply(200, decoded);
    } catch (err) {
        return Reply(403, err.message);
    }
}

async function login(address, signature, timestamp) {
    try {
        if (!address) {
            return Reply(400, "Invalid Login Request : No address");
        }

        if (!signature) {
            return Reply(400, "Invalid Login Request : No signature");
        }

        if (!timestamp) {
            return Reply(400, "Invalid Login Request : No timestamp");
        }
        var n_timestamp = Number(timestamp);

        // Verify if received timestamp is valid
        if (isNaN(n_timestamp)) {
            return Reply(401, "Invalid Login Request : Timestamp is NaN");
        }

        // Verify if received timestamp is older than current time
        if (n_timestamp >= clock()) {
            return Reply(401, "Invalid Timestamp : Future Timestamp");
        }

        // Verify if the address is whitelisted
        var last_timestamp = await getLastTimestamp(address);
        if (!last_timestamp) {
            return Reply(403, "Not Whitelisted");
        }

        // Verify if timestamp is fresh
        if (last_timestamp >= n_timestamp) {
            return Reply(401, "Replayed Timestamp");
        }

        // Verify if it is a valid signature
        var valid_signature = await verifySignature(address, signature, timestamp);
        if (!valid_signature) {
            return Reply(401, "Invalid Signature");
        }

        // Login suceded, update last_timestamp and return a new jwt

        await setLastTimestamp(address, n_timestamp);

        var token = getAuthToken(address);

        return Reply(200, token); // { auth: true, token: token }
    } catch (err) {
        return Reply(500, err.message);
    }
}

// API Endpoints

login_resource.get('/', (req, res) => {
    // Retrieve and send current monotonic timestamp
    res.json(clock().toString());
});

login_resource.post('/', async (req, res) => {
    // Parse parameters
    var address = req.body?.address;
    var signature = req.body?.signature;
    var timestamp = req.body?.timestamp;

    // Login
    var reply = await login(address, signature, timestamp);

    // Send Response
    res.status(reply.status).json(reply.body);

    // Log
    var str = (reply.status == 200 ? "" : " : " + reply.body);
    log.debug(`LOGIN ${address} -> ${res.statusCode} ${res.statusMessage}${str}`);
});

// Register the login resource
server.use("/login", login_resource);

// Enforce authorization verification of every non-login request
server.use('', (req, res, next) => {
    // Retrieve token from request headers
    const x = req.headers['x-access-token'];
    const a = req.headers['authorization'];
    const token = x ? x : (a ? a.split(' ')[1] : null);

    // Verify token
    var reply = verifyAuthToken(token);

    if (reply.status == 200) {
        next();
    } else {
        res.status(reply.status).send(reply.body);
    }
});

// Proxy endpoints
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
        BACKEND_URL.replace(/http[s]?:\/\//, "")
    ];
    await onReady(dependencies);

    // Initialize the database
    await initDB();

    // Start the web server
    /*const sv = */
    await server.listen(SERVER_PORT);

    log.debug(`Listening on TCP/${SERVER_PORT} ...\n`);
}
main();
