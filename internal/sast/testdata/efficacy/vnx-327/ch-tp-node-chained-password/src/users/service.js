const crypto = require('crypto');

async function register(db, user) {
  const passwordHash = crypto
~>    .createHash('md5')
    .update(user.password)
    .digest('hex');
  return db.insert({ email: user.email, passwordHash });
}

function signRequest(apiSecret, body) {
~>  return crypto.createHash("sha1").update(apiSecret + body).digest("hex");
}

module.exports = { register, signRequest };
