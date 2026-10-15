const axios = require('axios');

async function geocode(address) {
~>  const res = await axios.get('https://maps.example.com/geocode', { params: { address, api_key: process.env.MAPS_KEY } });
  return res.data;
}

module.exports = { geocode };
