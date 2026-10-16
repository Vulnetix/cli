const crypto = require('crypto');
const a = crypto.publicEncrypt(pem, buf);
const b = crypto.publicEncrypt({ key: pem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, buf);
// RSA_PKCS1_PADDING was removed
