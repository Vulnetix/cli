const fetch = require('node-fetch');

const UPSTREAM = 'https://api.internal/graphql';

async function deleteUser(req, res) {
  const userId = req.query.id;
~>  const q = 'mutation { deleteUser(id: "' + userId + '") { ok } }';
  const r = await fetch(UPSTREAM, { method: 'POST', body: JSON.stringify({ query: q }) });
  res.json(await r.json());
}

async function lookup(req, res) {
  const r = await fetch(UPSTREAM, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
~>    body: JSON.stringify({ query: `{ account(email: "${req.body.email}") { id plan } }` }),
  });
  res.json(await r.json());
}

module.exports = { deleteUser, lookup };
