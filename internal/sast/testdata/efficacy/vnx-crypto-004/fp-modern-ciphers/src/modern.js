const crypto = require('crypto')

function seal (key, data) {
  const iv = crypto.randomBytes(12)
  const c = crypto.createCipheriv('chacha20-poly1305', key, iv, { authTagLength: 16 })
  return Buffer.concat([iv, c.update(data), c.final(), c.getAuthTag()])
}

function aes (key, iv, data) {
  return crypto.createCipheriv('aes-256-gcm', key, iv).update(data)
}

// deliberately excluded legacy names, compared against configuration only
const DISALLOWED = new Set(['des-cbc', 'rc4', 'bf-cbc'])

module.exports = { seal, aes, DISALLOWED }
