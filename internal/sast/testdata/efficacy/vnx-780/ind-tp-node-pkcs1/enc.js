const crypto = require('crypto');
function seal(pem, buf) {
~>  return crypto.publicEncrypt({ key: pem, padding: crypto.constants.RSA_PKCS1_PADDING }, buf);
}
module.exports = { seal };
