const axios = require('axios');
const https = require('https');

const client = axios.create({
  baseURL: 'https://inventory.internal.example.com',
  timeout: 5000,
~>  httpsAgent: new https.Agent({ rejectUnauthorized: false }),
});

module.exports = client;
