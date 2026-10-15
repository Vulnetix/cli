const crypto = require('crypto');
const db = require('../db');

async function register(req, res) {
  const { username, password } = req.body;
  const hasher = crypto.createHash('sha256');
~>  hasher.update(password);
  const digest = hasher.digest('hex');
  await db.users.insert({ username, digest });
  res.status(201).end();
}

function legacyHash(password) {
  return crypto
    .createHash('md5')
~>    .update(password, 'utf8')
    .digest('hex');
}

module.exports = { register, legacyHash };
