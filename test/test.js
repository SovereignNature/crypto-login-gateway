const {
  mnemonicGenerate,
  mnemonicToMiniSecret,
  mnemonicValidate,
  naclKeypairFromSeed
} = require('@polkadot/util-crypto');
const { stringToU8a, u8aToHex } = require('@polkadot/util');
const { Keyring } = require('@polkadot/keyring');
const axios = require('axios');
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

const URL = Env("TEST_URL");

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

async function checkConnection() {
    var connected = false;
    for(var i = 0; i < 10; i++) {
        try {
            var resp = await axios.get(URL);
            if(resp.data) {
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
        throw Error(`Cannot connect to ${URL}!`);
    }
}

async function login(keypair) {
    var resp = await axios.get(URL);
    var timestamp = resp.data;

    const signature = u8aToHex(keypair.sign(stringToU8a(timestamp)));

    var credentials = {
        address: keypair.address,
        signature: signature,
        timestamp: timestamp
    };

    resp = await axios.post(URL, credentials);
    return resp.data;
}

async function main() {
    await checkConnection();

    // Create a keyring
    const keyring = new Keyring();
    const mnemonic = Env("TEST_MNEMONIC");
    const alice = keyring.addFromUri(mnemonic);

    var jwt = await login(alice);
    console.log("  > Alice" , alice.address, jwt != null);
}


if(process.argv[2] == "genaddress") {
    genAddress().catch(console.error).finally(() => process.exit());
} else {
    main().catch(console.error).finally(() => process.exit());
}
