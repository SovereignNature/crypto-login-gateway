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

const log4js = require("log4js");

const {
    Env,
    Reply,
    Sleep,
    Assert,
    checkDependencies
} = require("./utils.js");

const API_URL = Env("API_URL");
const N_CONNECTION_TRIES = Number(Env("N_CONNECTION_TRIES", 10));
const SLEEP_CONNECTION_TRIES = Number(Env("SLEEP_CONNECTION_TRIES", 1000));

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

async function genAddress() {
    // Create mnemonic string for Alice using BIP39
    const mnemonic = mnemonicGenerate();

    log.debug(`Mnemonic: ${mnemonic}`);

    // Validate the mnemic string that was generated
    const isValidMnemonic = mnemonicValidate(mnemonic);
    // log.debug(`isValidMnemonic: ${isValidMnemonic}`);

    const keyring = new Keyring();

    // Create and add the pair to the keyring
    const pair = keyring.addFromUri(mnemonic);

    // Print the address (encoded with the ss58Format)
    log.debug('Address: ', pair.address);
}

async function login(keypair, sig = undefined, ts = undefined) {
    try {
        let resp = await axios.get(API_URL + "/login");
        let timestamp = resp.data;

        const signature = u8aToHex(keypair.sign(stringToU8a(timestamp)));

        let credentials = {
            address: keypair.address,
            signature: sig ? sig : signature,
            timestamp: ts ? ts : timestamp
        };

        resp = await axios.post(API_URL + "/login", credentials);

        return Reply(resp.status, resp.data);
    } catch (err) {
        return Reply(err.response?.status, err.response?.data);
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

        let resp = await axios.get(API_URL + path, config);

        return Reply(resp.status, resp.data);
    } catch (err) {
        return Reply(err.response?.status, err.response?.data);
    }
}

async function main() {
    // Wait for web server
    await checkDependencies([API_URL], N_CONNECTION_TRIES, SLEEP_CONNECTION_TRIES);

    // Create a keyring
    const keyring = new Keyring();
    const alice = keyring.addFromUri(Env("TEST_MNEMONIC"));
    const bob = keyring.addFromUri(mnemonicGenerate());

    let reply = null;

    const Ax = (expected_status, reply) => Assert(reply.status == expected_status, `${reply.status} ${reply.body}`);

    // Sucess Login
    reply = await login(alice);
    Ax(200, reply);
    let token = reply.body;

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
    let ts = 3100;
    log.debug(`Sleep ${ts} ms ...`);
    await Sleep(ts);
    reply = await get("/", token);
    Ax(403, reply);
}

if (process.argv[2] == "genaddress") {
    genAddress().catch(console.error).finally(() => process.exit());
} else {
    main().catch(console.error).finally(() => process.exit());
}
