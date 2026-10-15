const axios = require('axios');

async function loadProfile(apiKey, id) {
~>  const res = await fetch(`https://api.example.com/users/${id}?apikey=${apiKey}`);
  return res.json();
}

function signIn(user, pass) {
~>  return axios.get('/auth/login?username=' + user + '&password=' + pass);
}

function list(secret) {
~>  return axios.get('/v2/list', { params: { client_secret: secret } });
}

module.exports = { loadProfile, signIn, list };
