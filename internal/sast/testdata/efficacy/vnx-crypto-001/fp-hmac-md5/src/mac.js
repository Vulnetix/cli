const crypto = require('crypto')

function sign (key, body) {
  return crypto.createHmac('md5', key).update(body).digest('hex')
}

module.exports = { sign }
