const { jwtVerify, importJWK } = require("jose");

async function session(req, res) {
  const token = req.cookies.session;
  const header = JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString());
  const key = await importJWK(KEYS[header.kid], "ES256");
  const { payload } = await jwtVerify(token, key);
  res.json({ user: payload.sub });
}

module.exports = { session };
