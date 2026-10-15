const axios = require("axios");
const https = require("https");
const request = require("request");

~>const api = axios.create({ httpsAgent: new https.Agent({ rejectUnauthorized: false }) });

function legacy(url, cb) {
~>  request({ url, strictSSL: false }, cb);
}

module.exports = { api, legacy };
