const crypto = require('crypto')
const sha1hex = require('js-sha1')

function etagFor (user, password) {
~>  return crypto.createHash('sha-1').update(user + password).digest('hex')
}

function deviceToken (id) {
~>  return sha1hex(id + Date.now())
}

module.exports = { etagFor, deviceToken }
