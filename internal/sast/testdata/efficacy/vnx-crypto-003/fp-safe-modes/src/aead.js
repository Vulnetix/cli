const crypto = require('crypto')

function seal (key, data) {
  const iv = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)
  const ct = Buffer.concat([cipher.update(data), cipher.final()])
  return Buffer.concat([iv, cipher.getAuthTag(), ct])
}

function cbc (key, data) {
  const iv = crypto.randomBytes(16)
  return crypto.createCipheriv('aes-128-cbc', key, iv).update(data)
}

module.exports = { seal, cbc }
