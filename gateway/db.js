const pg = require('pg');
//const readline = require('readline');
const csv = require('csv-parser');
const fsp = require('fs/promises');
fsp.constants = require('fs').constants;
//const fs = require('fs');
const log4js = require("log4js");

const log = log4js.getLogger("main");

var pool = null;

async function fillDB(whitelist_file) {
    return new Promise(
        async (resolve, reject) => {
            try {
                if(whitelist_file == "") {
                    return resolve(0);
                }

                await fsp.access(whitelist_file, fsp.constants.R_OK);

                let fd = await fsp.open(whitelist_file);

                // Create Table
                let res = await pool.query('CREATE TABLE whitelist (address VARCHAR(255) PRIMARY KEY, name VARCHAR(255), enabled BOOLEAN, last_timestamp BIGINT);');

                // Insert Entries
                let px = [];
                let inserted = 0;

                const parseRow = async (raw_row) => {
                    //console.log(raw_row);

                    let address = raw_row.address?.trim();
                    let name = String(raw_row.name?.trim());
                    let enabled = raw_row.enabled?.trim() == "true";
                    let last_timestamp = 0;

                    let p = pool.query("INSERT INTO whitelist (address, name, enabled, last_timestamp) VALUES ($1, $2, $3, $4);", [address, name, enabled, last_timestamp]);

                    px.push(p);
                }

                fd.createReadStream()
                    .pipe(csv({
                        separator: ';'
                    }))
                    .on('data', parseRow)
                    .on('end', async () => {
                        let inserted = (await Promise.all(px)).length;
                        resolve(inserted);
                        // console.log("WHITELIST", (await pool.query('SELECT * FROM whitelist')).rows);
                    });
            } catch (err) {
                reject(err)
            }
        }
    );
}

async function initDB(reset_whitelist, whitelist_file) {
    let table_exists = (await pool.query("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name='whitelist');")).rows[0]?.exists;

    let insert = false;

    if (table_exists) {
        if (reset_whitelist) {
            await pool.query('DROP TABLE whitelist;');

            log.debug("Whitelist cleared!");

            insert = true;
        } else {
            let n_addresses = (await pool.query("SELECT COUNT(address) FROM whitelist;")).rows[0]?.count;

            log.debug(`Whitelist already exists with ${n_addresses} addresses.`);
        }
    } else {
        insert = true;
    }

    if(insert) {
        let n_inserted = await fillDB(whitelist_file);
        log.debug(`Inserted ${n_inserted} entries in whitelist.`);
    }
}

async function getLastTimestamp(address) {
    return (await pool.query("SELECT last_timestamp FROM whitelist WHERE address=$1 AND enabled='true'", [address])).rows[0]?.last_timestamp;
}

async function setLastTimestamp(address, ts) {
    await pool.query('UPDATE whitelist SET last_timestamp = $1 WHERE address = $2', [ts, address]);
}

function DataBase(db_configs) {
    if(!pool) {
        pool = new pg.Pool(db_configs);
    }

    this.init = initDB;
    this.getLastTimestamp = getLastTimestamp;
    this.setLastTimestamp = setLastTimestamp;
}
module.exports.DataBase = DataBase;
