const crypto = require('crypto')

function signature (secret, body) {
  return 'sha1=' + crypto.createHmac('sha1', secret).update(body).digest('hex')
}

module.exports = { signature }
