"use strict";

const log = require("./log");


const get_data = async (pool, query) => {
    const client = await pool.connect();
    try {
        const res = await client.query(query);
        return res.rows;
    } catch (e) {
        log.error("Unable to execute statement in database: ", e);
        throw e;
    } finally {
        client.release();
    }
};

const execute_value = async (pool, query) => {
    const client = await pool.connect();
    try {
        await client.query("BEGIN");
        await client.query(query);
        await client.query("COMMIT");
    } catch (e) {
        await client.query("ROLLBACK");
        log.error("Unable to execute statement in database: ", e);
        throw e;
    } finally {
        client.release();
    }
};

const execute_values = async (pool, query) => {
    const client = await pool.connect();
    try {
        await client.query("BEGIN");
        for (let q of query) await client.query(q);
        await client.query("COMMIT");
    } catch (e) {
        await client.query("ROLLBACK");
        log.error("Unable to execute statement in database: ", e);
        throw e;
    } finally {
        client.release();
    }
};

module.exports = {
    get_data: get_data,
    execute_value: execute_value,
    execute_values: execute_values,
};
