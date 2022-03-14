const {
  mnemonicGenerate,
  mnemonicToMiniSecret,
  mnemonicValidate,
  naclKeypairFromSeed
} = require('@polkadot/util-crypto');
const { stringToU8a, u8aToHex } = require('@polkadot/util');
const { Keyring } = require('@polkadot/keyring');
const axios = require('axios');

async function genAddress() {
  // Create mnemonic string for Alice using BIP39
  const mnemonic = mnemonicGenerate();

  console.log(`Generated mnemonic: ${mnemonic}`);

  // Validate the mnemic string that was generated
  const isValidMnemonic = mnemonicValidate(mnemonic);
  console.log(`isValidMnemonic: ${isValidMnemonic}`);

  // Create valid Substrate-compatible seed from mnemonic
  // const seedAlice = mnemonicToMiniSecret(mnemonic);

  // Generate new public/secret keypair for Alice from the supplied seed
  // const { publicKey, secretKey } = naclKeypairFromSeed(seedAlice);

  const keyring = new Keyring(/*{ type: 'sr25519', ss58Format: 2 }*/);

  // Create and add the pair to the keyring
  const pair = keyring.addFromUri(mnemonic);

  // Print the address (encoded with the ss58Format)
  console.log('Address: ', pair.address);
}

async function main() {
    // create a keyring with some non-default values specified
    const keyring = new Keyring(/*{ type: 'sr25519', ss58Format: 2 }*/);

    const mnemonic = process.env.TEST_MNEMONIC;
    console.log(`mnemonic: ${mnemonic}`);

    const alice = keyring.addFromUri(mnemonic/*, { name: 'alice' }, 'ed25519'*/);

    console.log('Address: ', alice.address);

    const url = process.env.TEST_URL;

    var resp = await axios.get(url);

    var timestamp = resp.data;
    console.log(timestamp);

    const signature = u8aToHex(alice.sign(stringToU8a(timestamp)));

    console.log("Signature: " + signature);

    var credentials = {
        address: alice.address,
        signature: signature,
        timestamp: timestamp
    };

    resp = await axios.post(url, credentials);
    console.log("JWT: " + resp.data);
}

//console.log(process.argv);

if(process.argv[2] == "genaddress") {
    genAddress().catch(console.error).finally(() => process.exit());
} else {
    main().catch(console.error).finally(() => process.exit());
}
