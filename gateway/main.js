const express = require("express");
const bodyParser = require("body-parser");
const clock = require('monotonic-timestamp');
const jwt = require('jsonwebtoken');
const { signatureVerify } = require('@polkadot/util-crypto');
const { hexToU8a } = require('@polkadot/util');
const pg = require('pg');
const fs = require('fs/promises');
const net = require('net-promise');
const readline = require('readline');
const { createProxyMiddleware } = require('http-proxy-middleware');
const log4js = require("log4js");

function Env(key, default_value=undefined) {
    if(process.env[key]) {
        return process.env[key];
    } else {
        if(default_value) {
            return default_value;
        } else {
            throw `Invalid environment variable ${key}`;
        }
    }
}

const Sleep = ms => new Promise(r => setTimeout(r, ms));

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
  appenders: { out: { type: 'stdout', layout: {
      type: 'pattern',
      pattern: '%[[%d{dd-MM-yyyy hh:mm:ss}] %p ::%] %m',
  }}},
  categories: { default: { appenders: [ 'out' ], level: 'debug' } }
});
var log = log4js.getLogger();

// Configure Express
const router = express.Router();
const server = express();
server.use(bodyParser.urlencoded({ extended: false }));
server.use(bodyParser.json());

// Configure DB Connection
const db = new pg.Pool({
  host: POSTGRES_HOST,
  database: POSTGRES_DB,
  user: POSTGRES_USER,
  password: POSTGRES_PASSWORD,
  port: POSTGRES_PORT,
});

// Auxiliary Functions and Variables

async function checkConnection(dep) {
    return new Promise( async (resolve, reject) => {
        var aux = dep.split(":");
        var host = aux[0];
        var port = Number(aux[1] ? aux[1] : "80");

        var connected = false;
        for(var i = 0; i < N_CONNECTION_TRIES && !connected; i++) {
            try {

                var client = await net.Socket({host: host, port: port});
                connected = true;
                client.close();

            } catch(err) {
                // Ignore and try again
                await Sleep(1000);

                log.debug(`Re-trying to connect to ${dep} (attempt ${i+1}/${N_CONNECTION_TRIES}) ...`);
            }
        }
        if(N_CONNECTION_TRIES > 0) {
            if(!connected) {
                reject(Error(`Cannot connect to ${dep}`));
            } else {
                log.debug(`Connected to ${dep}`);

                resolve();
            }
        } else {
            resolve();
        }
    } );
}

async function dependencies(deps) {
    var px = [];

    deps.forEach((dep, i) => {
        var p = checkConnection(dep);
        px.push(p);
    });

    return Promise.all(px);
}

async function fillDB() {

    // Create Table
    var res = await db.query('CREATE TABLE whitelist (address varchar(255), last_timestamp varchar(255));');

    // Insert Entries
    try {
        await fs.access(WHITELIST_FILE, require('fs').constants.R_OK);

        var p = new Promise( async (resolve, reject) => {
            var px = [];
            var inserted = 0;

            var fd = await fs.open(WHITELIST_FILE);
            var reader = readline.createInterface({
              input: fd.createReadStream(),
              crlfDelay: Infinity
            });

            for await (const line of reader) {
                var p = db.query("INSERT INTO whitelist (address, last_timestamp) VALUES ($1, $2);", [line.trim(), 0]);

                inserted++;

                px.push(p);
            }
            Promise.all(px);
            resolve(inserted);
        });

        return await p;
    } catch (err) {
        log.debug(err);

        process.exit();
    }
}

async function initDB() {

    var table_exists = (await db.query("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name='whitelist');")).rows[0]?.exists;

    if( table_exists ) {
        if( RESET_WHITELIST ) {
            await db.query('DROP TABLE whitelist;');

            log.debug("Whitelist cleared!");

            var n_inserted = await fillDB();
            log.debug(`Inserted ${n_inserted} entries in whitelist.`);
        } else {
            var n_addresses = (await db.query("SELECT COUNT() FROM whitelist;")).rows[0]?.count;

            log.debug(`Whitelist already exists with ${n_addresses} addresses.`);
        }
    } else {
        var n_inserted = await fillDB();
        log.debug(`Inserted ${n_inserted} entries in whitelist.`);
    }
}

async function getLastTimestamp(address) {
    return (await db.query('SELECT last_timestamp FROM whitelist WHERE address=$1', [address])).rows[0]?.last_timestamp;
}

async function setLastTimestamp(address, ts) {
    await db.query('UPDATE whitelist SET last_timestamp = $1 WHERE address = $2', [ts, address]);
}

function validSignature(address, signature, data) {
    return signatureVerify(data, hexToU8a(signature), address).isValid;
}

function getAuthToken(address) {
    return jwt.sign({address: address}, JWT_SECRET, { expiresIn: JWT_DURATION+'s' });
}

// API Endpoints

router.get('/', (req,res) => {
    // Retrieve and send current monotonic timestamp
    res.send(clock().toString()).end();
});

router.post('/', async (req,res) => {

    var address = undefined;
    var signature = undefined;
    var timestamp = undefined;
    var msg = "";

    // Verify if the request is valid
    if(req.body.address && req.body.signature && req.body.timestamp) {
        address = req.body.address;
        signature = req.body.signature;
        timestamp = req.body.timestamp;

        // Verify if received timestamp is valid
        var n_timestamp = Number(timestamp);
        if(n_timestamp < clock()) {

            // Verify if the address is whitelisted
            var last_timestamp = await getLastTimestamp(address);
            var is_whitelisted = last_timestamp != null && last_timestamp != undefined;
            if(is_whitelisted) {

                // Verify if timestamp is fresh
                if(last_timestamp < n_timestamp) {
                    // Verify if it is a valid signature
                    if(validSignature(address, signature, timestamp)) {

                        await setLastTimestamp(address, n_timestamp);

                        var token = getAuthToken(address);

                        msg = "";
                        res.json(token);
                        // return res.json({ auth: true, token: token });
                    } else {
                        msg = "Invalid Signature";
                        res.status(401).send(msg);
                    }
                } else {
                    msg = "Replayed Timestamp";
                    res.status(401).send(msg);
                }
            } else {
                msg = "Not Whitelisted";
                res.status(403).send(msg);
            }
        } else {
            msg = "Invalid Timestamp";
            res.status(401).send(msg);
        }
    } else {
        msg = "Invalid Login Request";
        res.status(400).send(msg);
    }

    // Log request
    var str = (msg!=""? " : " + msg : "");
    log.debug(`LOGIN: ${address} -> ${res.statusCode} ${res.statusMessage}${str}`);
    res.end();
});

// Add router to the Express server
server.use("/login", router);

// Authorization
server.use('', (req, res, next) => {
    const x = req.headers['x-access-token'];
    const a = req.headers['authorization'];
    const token = x ? x : (a ? a.split(' ')[1] : null);

    if(token) {
        try {
            var decoded = jwt.verify(token, JWT_SECRET);
            //console.log(decoded);

            next();
        } catch(err) {
            //console.log(err);
            res.status(403).send(err.message);
        }
    } else {
        //res.status(401).json({ auth: false, message: 'No token provided.' });
        res.status(401).send('No token provided.');
    }
});

// Proxy endpoints
server.use('/', createProxyMiddleware({
    target: BACKEND_URL,
    changeOrigin: false
    /*pathRewrite: {
        [`^/json_placeholder`]: '',
    },*/
}));

async function main() {

    log.debug(`crypto-login ${IMG_TAG}`);

    // Wait for the dependencies to initialize
    await dependencies([
        `${POSTGRES_HOST}:${POSTGRES_PORT}`,
        BACKEND_URL.replace(/http[s]?:\/\//, "")
    ]);

    // Initialize the database
    await initDB();

    // Start the web server
    /*const sv = */await server.listen(SERVER_PORT);

    log.debug(`Listening on tcp/${SERVER_PORT} ...\n`);
}
main();
