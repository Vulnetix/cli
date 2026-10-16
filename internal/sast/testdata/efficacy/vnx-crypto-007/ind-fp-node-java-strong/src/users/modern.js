const crypto = require('crypto');
const bcrypt = require('bcrypt');
const security = require('../security');

async function hashPassword(password) {
  return bcrypt.hash(password, 12);
}

function scryptPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function viaHelper(password) {
  return security.hash(password);
}

function cacheKey(req) {
  return crypto.createHash('sha256').update(req.originalUrl).digest('hex');
}

module.exports = { hashPassword, scryptPassword, viaHelper, cacheKey };
