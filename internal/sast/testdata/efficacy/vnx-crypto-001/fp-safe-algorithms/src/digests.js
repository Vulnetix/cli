const crypto = require('crypto')

function checksum (buf) {
  return crypto.createHash('sha256').update(buf).digest('hex')
}

function md5Free (buf) {
  const alg = 'sha512'
  return crypto.createHash(alg).update(buf).digest('hex')
}

module.exports = { checksum, md5Free }
