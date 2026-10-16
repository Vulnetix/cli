const crypto = require('crypto');

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

function acceptKey(secWebSocketKey) {
  return crypto.createHash('sha1').update(secWebSocketKey + GUID).digest('base64');
}

module.exports = { acceptKey };
