const crypto = require('crypto');

function storeUser(db, name, password) {
  const h = crypto.createHash('sha256');
~>  h.update(password);
  const digest = h.digest('hex');
  return db.insert({ name, digest });
}

module.exports = { storeUser };
