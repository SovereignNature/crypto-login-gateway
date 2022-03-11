const express = require("express");
const bodyParser = require("body-parser");
const router = express.Router();
const app = express();
const clock = require('monotonic-timestamp');

const port = 80;

// Configure Express
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Auxiliary Functions and Variables

const key_db = ["my_pub_key"];

function whiteListed(pubkey) {
    // TODO: Turn into a DB later
    return key_db.includes(pubkey);
}

function validSignature(pubkey, signature, data) {
    return signature == data;
}

function getAuthToken() {
    // TODO: generate cookie or jwt
    return "yes";
}

// API Endpoints

router.get('/', (req,res) => {
    // Retrieve and send current monotonic timestamp
    var timestamp = clock().toString();
    res.end(timestamp);
});

router.post('/', (req,res) => {

    // Verify if the request is valid
    if(req.body.pubkey && req.body.signature && req.body.timestamp) {
        var pubkey = req.body.pubkey;
        var signature = req.body.signature;
        var timestamp = req.body.timestamp;

        // Verify if received timestamp is valid
        if(Number(timestamp) < clock()) {

            // Verify if the pubkey is whitelisted
            if(whiteListed(pubkey)) {

                // Verify if it is a valid signature
                if(validSignature(pubkey, signature, timestamp)) {
                    res.end(getAuthToken());
                } else {
                    res.status(401).end("Invalid Signature");
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
app.listen(port, () => {
    console.log(`Listenning on PORT ${port}`);
});
