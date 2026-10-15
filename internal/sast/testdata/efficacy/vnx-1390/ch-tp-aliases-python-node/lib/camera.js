const DigestClient = require('digest-fetch');

async function snapshot(url, user, pass) {
~>  const client = new DigestClient(user, pass, { algorithm: 'MD5' });
  const res = await client.fetch(url);
  return res.buffer();
}

module.exports = { snapshot };
