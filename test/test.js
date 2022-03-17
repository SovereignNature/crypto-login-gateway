const {
  mnemonicGenerate,
  mnemonicToMiniSecret,
  mnemonicValidate,
  naclKeypairFromSeed
} = require('@polkadot/util-crypto');
const { stringToU8a, u8aToHex } = require('@polkadot/util');
const { Keyring } = require('@polkadot/keyring');
const axios = require('axios');
const net = require('net-promise');
//const pg = require('pg');

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

//const LOGIN_URL = Env("LOGIN_URL");
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
                //console.log(err);
                // Ignore and try again
                await Sleep(1000);

                console.log(`Re-trying to connect to ${dep} (attempt ${i+1}/${N_CONNECTION_TRIES}) ...`);
            }
        }
        if(N_CONNECTION_TRIES > 0) {
            if(!connected) {
                reject(Error(`Cannot connect to ${dep}`));
            } else {
                console.log(`Connected to ${dep}`);

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

async function login(keypair) {
    var resp = await axios.get(API_URL + "/login");
    var timestamp = resp.data;

    const signature = u8aToHex(keypair.sign(stringToU8a(timestamp)));

    var credentials = {
        address: keypair.address,
        signature: signature,
        timestamp: timestamp
    };

    resp = await axios.post(API_URL + "/login", credentials);
    return resp.data;
}

async function get(path, jwt) {
    try {
        const config = {
            headers: {
                "x-access-token": jwt,
                //authorization: `Bearer ${jwt}`
            }
        };
        var resp = await axios.get(API_URL + path, config);
        return resp.data;
    } catch(err) {
        return {status: err.response?.status, message: err.response?.data};
    }
}

async function main() {
    await dependencies([API_URL.replace(/http[s]?:\/\//, "")]);

    // Create a keyring
    const keyring = new Keyring();
    const mnemonic = Env("TEST_MNEMONIC");
    const alice = keyring.addFromUri(mnemonic);

    var jwt = await login(alice);
    console.log("  > Alice" , alice.address, jwt != null);

    var res = await get("/", jwt);
    console.log(res);
}


if(process.argv[2] == "genaddress") {
    genAddress().catch(console.error).finally(() => process.exit());
} else {
    main().catch(console.error).finally(() => process.exit());
}
