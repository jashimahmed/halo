"use strict";

const moment = require("moment");
const uuid = require("uuid");
const JWT = require("jsonwebtoken");
const Dao = require("./dao");
const { ALGORITHM, BEARER, SCHEMA, TABLE } = require("./constant");

const generate_token = (token) => {
    const access_token = get_access_token(token);

    const response = {
        access_token: access_token,
        token_type: BEARER,
        access_token_expire_in: process.env.ACCESS_TOKEN_SECRET_EXPIRE,
    };

    return response;
};

const get_access_token = (token) => {
    return JWT.sign(token, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: process.env.ACCESS_TOKEN_SECRET_EXPIRE,
        algorithm: ALGORITHM,
    });
};

const get_access_token_from_db = async (request) => {
    let data = null;
    let access_token = request.headers["authorization"].replace("Bearer ", "").trim();
    let sql = {
        text: `select lower(status) as status, to_char(sign_out_time, 'YYYY-MM-DD HH24:MI:SS.MS') as sign_out_time
            from ${SCHEMA.PUBLIC}.${TABLE.LOGINLOG} 
            where 1 = 1 and access_token = $1`,
        values: [access_token],
    };
    try {
        let data_set = await Dao.get_data(request.pg, sql);
        data = data_set[0];
    } catch (e) {
        log.error(`An exception occurred while getting login log : ${e?.message}`);
    }
    return data;
};

module.exports = {
    generate_token: generate_token,
    get_access_token: get_access_token,
    get_access_token_from_db: get_access_token_from_db,
};
