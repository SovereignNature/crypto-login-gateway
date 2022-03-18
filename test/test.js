const {
    mnemonicGenerate,
    mnemonicToMiniSecret,
    mnemonicValidate,
    naclKeypairFromSeed
} = require('@polkadot/util-crypto');
const {
    stringToU8a,
    u8aToHex
} = require('@polkadot/util');
const {
    Keyring
} = require('@polkadot/keyring');
const axios = require('axios');
const net = require('net-promise');
//const pg = require('pg');

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

const Assert = (expr, msg = undefined) => {
    var status, color;
    if (expr) {
        status = "OK";
        color = "32";
    } else {
        status = "FAILED";
        color = "31";
    }

    var str = "";
    if (msg) {
        str = ` : ${String(msg).trim()}`;
    }

    console.log(`\x1b[${color}m [${status}] \x1b[0m ${str}`);
};

const API_URL = Env("API_URL");
const N_CONNECTION_TRIES = Number(Env("N_CONNECTION_TRIES", 10));


async function genAddress() {
    // Create mnemonic string for Alice using BIP39
    const mnemonic = mnemonicGenerate();

    console.log(`Mnemonic: ${mnemonic}`);

    // Validate the mnemic string that was generated
    const isValidMnemonic = mnemonicValidate(mnemonic);
    // console.log(`isValidMnemonic: ${isValidMnemonic}`);

    const keyring = new Keyring();

    // Create and add the pair to the keyring
    const pair = keyring.addFromUri(mnemonic);

    // Print the address (encoded with the ss58Format)
    console.log('Address: ', pair.address);
}

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
                //console.log(err);
                // Ignore and try again
                await Sleep(1000);

                console.log(`Re-trying to connect to ${dep} (attempt ${i+1}/${N_CONNECTION_TRIES}) ...`);
            }
        }
        if (N_CONNECTION_TRIES > 0) {
            if (!connected) {
                reject(Error(`Cannot connect to ${dep}`));
            } else {
                console.log(`Connected to ${dep}`);

                resolve();
            }
        } else {
            resolve();
        }
    });
}

async function dependencies(deps) {
    var px = [];

    deps.forEach((dep, i) => {
        var p = checkConnection(dep);
        px.push(p);
    });

    return Promise.all(px);
}

async function login(keypair, sig = undefined, ts = undefined) {
    try {
        var resp = await axios.get(API_URL + "/login");
        var timestamp = resp.data;

        const signature = u8aToHex(keypair.sign(stringToU8a(timestamp)));

        var credentials = {
            address: keypair.address,
            signature: sig ? sig : signature,
            timestamp: ts ? ts : timestamp
        };

        resp = await axios.post(API_URL + "/login", credentials);

        return {
            status: resp.status,
            body: resp.data
        };
    } catch (err) {
        return {
            status: err.response?.status,
            body: err.response?.data
        };
    }
}

async function get(path, jwt, option = 1) {
    try {
        const config = {
            headers: {}
        };
        if (jwt) {
            if (option == 1) {
                config.headers["x-access-token"] = jwt;
            } else if (option == 2) {
                config.headers.authorization = `Bearer ${jwt}`;
            }
        }

        var resp = await axios.get(API_URL + path, config);

        return {
            status: resp.status,
            body: resp.data
        };
    } catch (err) {
        return {
            status: err.response?.status,
            body: err.response?.data
        };
    }
}

async function main() {
    // Wait for web server
    await dependencies([API_URL.replace(/http[s]?:\/\//, "")]);

    // Create a keyring
    const keyring = new Keyring();
    const alice = keyring.addFromUri(Env("TEST_MNEMONIC"));
    const bob = keyring.addFromUri(mnemonicGenerate());

    var reply = null;

    const Ax = (expected_status, reply) => Assert(reply.status == expected_status, `${reply.status} ${reply.body}`);

    // Sucess Login
    reply = await login(alice);
    Ax(200, reply);
    var token = reply.body;

    // Not Whitelisted
    reply = await login(bob);
    Ax(403, reply);

    // Invalid Signature
    reply = await login(alice, "adarawdasd");
    Ax(401, reply);

    // Timestamp is NaN
    reply = await login(alice, undefined, "hjvvilvhvl");
    Ax(401, reply);

    // Replayed Timestamp
    reply = await login(alice, undefined, "1");
    Ax(401, reply);

    // Future Timestamp
    reply = await login(alice, undefined, "99999999999999");
    Ax(401, reply);

    // Sucessfull Request
    reply = await get("/", token);
    Ax(200, reply);

    // jwt malformed
    reply = await get("/", "ausidfgas");
    Ax(403, reply);

    // No Token Provided
    reply = await get("/", undefined);
    Ax(401, reply);

    // No Token Provided
    reply = await get("/", null);
    Ax(401, reply);

    // No Token Provided
    reply = await get("/", "");
    Ax(401, reply);

    // jwt expired
    await Sleep(3100);
    reply = await get("/", token);
    Ax(403, reply);
}

if (process.argv[2] == "genaddress") {
    genAddress().catch(console.error).finally(() => process.exit());
} else {
    main().catch(console.error).finally(() => process.exit());
}
