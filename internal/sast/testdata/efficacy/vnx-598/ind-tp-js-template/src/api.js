const axios = require('axios');

async function items(token) {
~>  return axios.get(`https://api.example.com/v1/items?access_token=${token}`);
}

async function search(q, apiKey) {
~>  return axios.get(url, { params: { q: q, api_key: apiKey } });
}
