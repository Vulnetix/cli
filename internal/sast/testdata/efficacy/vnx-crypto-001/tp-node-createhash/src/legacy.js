const crypto = require('crypto')
const toMd5 = require('blueimp-md5')

function signUpload (buf) {
~>  const sum = crypto.createHash('md5')
  sum.update(buf)
  return sum.digest('hex')
}

function sign (key, data) {
~>  const signer = crypto.createSign('RSA-MD5')
  signer.update(data)
  return signer.sign(key, 'hex')
}

function token (user) {
~>  return toMd5(user + ':' + process.env.SALT)
}

module.exports = { signUpload, sign, token }
