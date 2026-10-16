const crypto = require('crypto');
const fs = require('fs');

function checksum(file) {
  return crypto.createHash('sha1').update(fs.readFileSync(file)).digest('hex');
}

module.exports = { checksum };
