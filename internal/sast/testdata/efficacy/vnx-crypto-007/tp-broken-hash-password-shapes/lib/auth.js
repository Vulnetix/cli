const crypto = require('crypto');
const CryptoJS = require('crypto-js');

function hashPassword(password) {
~>  const a = crypto.createHash('md5').update(password).digest('hex');
~>  const b = CryptoJS.MD5(password).toString();
  return a + b;
}
