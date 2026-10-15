const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const ROUNDS = 12;
const ITER = 310000;
exports.a = (password, salt) => crypto.pbkdf2Sync(password, salt, ITER, 32, "sha256");
exports.b = (password) => bcrypt.hash(password, ROUNDS);
