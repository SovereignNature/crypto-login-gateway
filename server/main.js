const express = require("express");
const bodyParser = require("body-parser");
const router = express.Router();
const app = express();
const clock = require('monotonic-timestamp');
const jwt = require('jsonwebtoken');
const { signatureVerify } = require('@polkadot/util-crypto');
const { hexToU8a } = require('@polkadot/util');
const pg = require('pg');
const fs = require('fs/promises');
const readline = require('readline');

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

const PORT = Number(Env("APP_PORT", 80));
const JWT_SECRET = Env("JWT_SECRET");
const JWT_DURATION = Number(Env("JWT_DURATION", 1800));

// Configure Express
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Configure DB Connection
const db = new pg.Pool({
  host: Env("POSTGRES_HOST"),
  database: Env("POSTGRES_DB"),
  user: Env("POSTGRES_USER"),
  password: Env("POSTGRES_PASSWORD"),
  port: Number(Env("POSTGRES_PORT")),
});

// Auxiliary Functions and Variables

async function checkConnection() {
    var connected = false;
    for(var i = 0; i < 10; i++) {
        try {
            var res = await db.query('SELECT NOW()');
            if(res) {
                // console.log(res);
                connected = true;
                break;
            }
        } catch(err) {
            // Ignore and try again
            // console.log(err);
            await Sleep(1000);
        }
    }
    if(!connected) {
        throw Error("Cannot connect to database!");
    } else {
        console.log("Connected to DB!");
    }
}

async function initDB() {

    await checkConnection();

    var table_exists = (await db.query("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name='whitelist');")).rows[0]?.exists;

    if(!table_exists) {
        // Create Table
        var res = await db.query('CREATE TABLE whitelist (address varchar(255), last_timestamp varchar(255));');

        // Insert Entries
        try {
            var file = '/login-api/whitelist.txt';
            await fs.access(file, require('fs').constants.R_OK);

            var p = new Promise( async (resolve, reject) => {
                var px = [];
                var inserted = 0;

                var fd = await fs.open(file);
                var reader = readline.createInterface({
                  input: fd.createReadStream(),
                  crlfDelay: Infinity
                });

                for await (const line of reader) {
                    console.log(`Line from file: ${line}`);

                    var p = db.query("INSERT INTO whitelist (address, last_timestamp) VALUES ($1, $2);", [line.trim(), 0]);

                    inserted++;

                    px.push(p);
                }
                Promise.all(px);
                resolve(inserted);
            });

            var inserted = await p;
            console.log(`Inserted ${inserted} entries in whitelist.`);
        } catch (err) {
            console.log(err);
            console.log("Whitelist file does not exist!");
            process.exit();
        }
    } else {
        console.log("Whitelist already exists.");
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
    res.end(clock().toString());
});

router.post('/', async (req,res) => {

    // Verify if the request is valid
    if(req.body.address && req.body.signature && req.body.timestamp) {
        var address = req.body.address;
        var signature = req.body.signature;
        var timestamp = req.body.timestamp;

        // Verify if received timestamp is valid
        var n_timestamp = Number(timestamp);
        if(n_timestamp < clock()) {

            // Verify if the address is whitelisted
            var last_timestamp = await getLastTimestamp(address);
            var is_whitelisted = last_timestamp != null && last_timestamp != undefined;
            if(is_whitelisted) {

                console.log(last_timestamp, n_timestamp);

                // Verify if timestamp is fresh
                if(last_timestamp < n_timestamp) {
                    // Verify if it is a valid signature
                    if(validSignature(address, signature, timestamp)) {

                        await setLastTimestamp(address, n_timestamp);

                        res.json(getAuthToken(address)).end();
                    } else {
                        res.status(401).end("Invalid Signature");
                    }
                } else {
                    res.status(401).end("Replayed Timestamp");
                }
            } else {
                res.status(403).end("Not Whitelisted");
            }
        } else {
            res.status(401).end("Invalid Timestamp");
        }
    } else {
        res.status(400).end("Invalid Login Request");
    }
});

// Add router to the Express app
app.use("/", router);

async function main() {
    // InitDB
    await initDB();

    // Start the web server
    app.listen(PORT, () => {
        console.log(`Listenning on PORT ${PORT}`);
    });
}

main();
