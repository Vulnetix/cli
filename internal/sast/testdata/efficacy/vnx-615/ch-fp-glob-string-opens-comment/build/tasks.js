const glob = require('glob');

const files = glob.sync("src/**/*.js");
const api_key = process.env.API_KEY;
const password = readSecret('db');
module.exports = { files, api_key, password };
