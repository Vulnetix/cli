const crypto = require('crypto')

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

// RFC 6455 fixes SHA-1 for the opening handshake; it protects nothing.
function acceptKey (key) {
  return crypto.createHash('sha1')
    .update(key + GUID)
    .digest('base64')
}

module.exports = { acceptKey }
