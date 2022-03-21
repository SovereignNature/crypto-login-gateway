const clock = require('monotonic-timestamp');
const jwt = require('jsonwebtoken');
const {
    signatureVerify
} = require('@polkadot/util-crypto');
const {
    hexToU8a
} = require('@polkadot/util');

const log4js = require("log4js");

const log = log4js.getLogger("main");

const {
    Reply
} = require("./utils.js");

var jwt_secret;
var jwt_duration;
var db;

function getNonce() {
    return clock().toString();
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
    }, jwt_secret, {
        expiresIn: `${jwt_duration}s`
    });
}

function verifyAuthToken(token) {
    if (!token || token == "")
        return Reply(401, 'No Token Provided');

    try {
        let decoded = jwt.verify(token, jwt_secret);

        return Reply(200, decoded);
    } catch (err) {
        return Reply(403, err.message);
    }
}

async function login(address, signature, timestamp) {
    try {
        if (!address)
            return Reply(400, "Invalid Login Request : No address");

        if (!signature)
            return Reply(400, "Invalid Login Request : No signature");

        if (!timestamp)
            return Reply(400, "Invalid Login Request : No timestamp");

        let n_timestamp = Number(timestamp);

        // Verify if received timestamp is valid
        if (isNaN(n_timestamp))
            return Reply(401, "Invalid Login Request : Timestamp is NaN");

        // Verify if received timestamp is older than current time
        if (n_timestamp >= clock())
            return Reply(401, "Invalid Timestamp : Future Timestamp");

        // Verify if the address is whitelisted
        let last_timestamp = await db.getLastTimestamp(address);
        if (!last_timestamp)
            return Reply(403, "Not Whitelisted");

        // Verify if timestamp is fresh
        if (last_timestamp >= n_timestamp)
            return Reply(401, "Replayed Timestamp");

        // Verify if it is a valid signature
        let valid_signature = await verifySignature(address, signature, timestamp);
        if (!valid_signature)
            return Reply(401, "Invalid Signature");

        // Login suceded, update last_timestamp and return a new jwt

        await db.setLastTimestamp(address, n_timestamp);

        let token = getAuthToken(address);

        return Reply(200, token); // { auth: true, token: token }
    } catch (err) {
        return Reply(500, err.message);
    }
}

function Auth(jwt_secret_, jwt_duration_, db_) {
    if(!db_)
        throw new Error("DB is undefined!");

    if(!jwt_secret) {
        jwt_secret = jwt_secret_;
        jwt_duration = jwt_duration_;
        db = db_;
    }

    this.getNonce = getNonce;
    this.verifySignature = verifySignature;
    this.getAuthToken = getAuthToken;
    this.verifyAuthToken = verifyAuthToken;
    this.login = login;
}
module.exports.Auth = Auth;
