const {
    URL
} = require('url');
const {
    Socket
} = require('net-promise');

const log4js = require("log4js");
const log = log4js.getLogger("main");


const Err = (msg) => {
    throw new Error(msg)
};
module.exports.Err = Err;

const Assert = (expr, msg = undefined) => {
    let status, color;
    if (expr) {
        status = "OK";
        color = "32";
    } else {
        status = "FAILED";
        color = "31";
    }

    let str = "";
    if (msg) {
        str = ` : ${String(msg).trim()}`;
    }

    log.debug(`\x1b[${color}m [${status}] \x1b[0m ${str}`);
};
module.exports.Assert = Assert;

const Env = (key, default_value = undefined) => {
    return process.env[key] ?? (default_value ?? Err(`Environment Variable ${key} Not Defined`));
}
module.exports.Env = Env;

const Sleep = async ms => new Promise(r => setTimeout(r, ms));
module.exports.Sleep = Sleep;

const Reply = (status = 200, body = "") => ({
    status: status,
    body: body
});
module.exports.Reply = Reply;

function parseURL(url) {
    if(!url.includes("://") || url.includes("tcp://") ) {

        let aux = url.replace("tcp://").split(":");
        connection_config = {
            host: aux[0],
            port: Number(aux[1])
        };
    } else {
        let dep = new URL(url);

        const protocols = {
            ftp: 21,
            gopher: 70,
            http: 80,
            https: 443,
            ws: 80,
            wss: 443,
        };
        const port = dep.port != '' ? Number(dep.port) : protocols[dep.protocol.replace(":", "")];

        connection_config = {
            host: dep.hostname,
            port: port
        };
    }

    //console.log(dep_url, connection_config);

    if(!connection_config.port || isNaN(connection_config.port)) {
        Err("No port!");
    }

    return connection_config;
}

const checkConnection = async (dep_url, max_tries = 3, sleep = 1000) => new Promise(
    async (resolve, reject) => {
        let connection_config;

        try {
            connection_config = parseURL(dep_url);
        } catch (err) {
            return reject(new Error(`Invalid Dependency : ` + err.message));
        }

        let connected = false;
        for (let i = 0; i < max_tries && !connected; i++) {
            try {
                let client = await Socket(connection_config);
                connected = true;
                client.close();
            } catch (err) {
                // Ignore and try again
                await Sleep(sleep);

                log.debug(`Re-trying to connect to ${dep_url} (attempt ${i+1}/${max_tries}) ...`);
            }
        }
        if (max_tries > 0) {
            if (!connected) {
                reject(new Error(`Cannot connect to ${dep_url}`));
            } else {
                log.debug(`Connected to ${dep_url}`);

                resolve();
            }
        } else {
            resolve();
        }
    }
);
module.exports.checkConnection = checkConnection;

const checkDependencies = async (deps, max_tries=3, sleep) => {
    let px = [];

    deps.forEach((dep_url, i) => {
        let p = checkConnection(dep_url, max_tries, sleep);
        px.push(p);
    });

    return Promise.all(px);
}
module.exports.checkDependencies = checkDependencies;
