const crypto = require('crypto')

function integrity (buf) {
  return 'sha384-' + crypto.createHash('sha384').update(buf).digest('base64')
}

function sign (key, data) {
  return crypto.createSign('RSA-SHA256').update(data).sign(key, 'hex')
}

module.exports = { integrity, sign }
