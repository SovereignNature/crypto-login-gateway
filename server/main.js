const express = require("express");
const bodyParser = require("body-parser");
const router = express.Router();
const app = express();
const clock = require('monotonic-timestamp');
const jwt = require('jsonwebtoken');
const { signatureVerify } = require('@polkadot/util-crypto');
const { hexToU8a } = require('@polkadot/util');

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

const PORT = Number(Env("APP_PORT", 80));
const JWT_SECRET = Env("JWT_SECRET");
const JWT_DURATION = Number(Env("JWT_DURATION", 1800));

// Configure Express
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Auxiliary Functions and Variables

const key_db = {};
key_db[Env("TEST_ADDRESS")] = 0;

function getLastTimestamp(address) {
    return key_db[address];
}

function setLastTimestamp(address, t) {
    key_db[address] = t;
}

/*function whiteListed(address) {
    // TODO: Turn into a DB later
    return key_db.includes(address);
}*/

function validSignature(address, signature, data) {
    const { isValid } = signatureVerify(data, hexToU8a(signature), address);
    return isValid; // TODO
}

function getAuthToken(address) {
    return jwt.sign({address: address}, JWT_SECRET, { expiresIn: JWT_DURATION+'s' });
}

// API Endpoints

router.get('/', (req,res) => {
    // Retrieve and send current monotonic timestamp
    res.end(clock().toString());
});

router.post('/', (req,res) => {

    // Verify if the request is valid
    if(req.body.address && req.body.signature && req.body.timestamp) {
        var address = req.body.address;
        var signature = req.body.signature;
        var timestamp = req.body.timestamp;

        // Verify if received timestamp is valid
        var n_timestamp = Number(timestamp);
        if(n_timestamp < clock()) {

            // Verify if the address is whitelisted
            var last_timestamp = getLastTimestamp(address);
            var is_whitelisted = last_timestamp != null && last_timestamp != undefined;
            if(is_whitelisted) {

                // Verify if timestamp is fresh
                if(last_timestamp < n_timestamp) {
                    // Verify if it is a valid signature
                    if(validSignature(address, signature, timestamp)) {

                        setLastTimestamp(address, n_timestamp);

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

// Start the web server
app.listen(PORT, () => {
    console.log(`Listenning on PORT ${PORT}`);
});
