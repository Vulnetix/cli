const crypto = require("crypto");
const bcrypt = require("bcrypt");

async function register(req) {
~>  const hashed = crypto.createHash("sha256").update(req.body.password).digest("hex");
~>  const b = await bcrypt.hash(req.body.password, 8);
~>  const k = crypto.pbkdf2Sync(req.body.password, salt, 1000, 64, "sha512");
  return { hashed, b, k };
}
module.exports = { register };
