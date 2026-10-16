const axios = require('axios');

const billing = axios.create({
  baseURL: 'https://billing.acme-corp.io',
  headers: {
~>    Authorization: 'Basic YmlsbGluZy1zdmM6UnQ3eVF3M1prOUxwMlh2',
    Accept: 'application/json',
  },
});
module.exports = billing;
