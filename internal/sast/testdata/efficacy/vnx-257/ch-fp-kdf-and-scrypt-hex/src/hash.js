const crypto = require("crypto");

function hashPassword(password, salt) {
  return crypto.scryptSync(Buffer.from(password), salt, 64).toString("hex");
}

function hashPassword2(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 310000, 32, "sha256").toString("base64");
}
