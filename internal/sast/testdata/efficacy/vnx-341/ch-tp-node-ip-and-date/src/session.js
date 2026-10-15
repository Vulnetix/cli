const crypto = require('crypto');

function startSession(req) {
~>  const sessionId = crypto.createHash('md5').update(req.ip + Date.now()).digest('hex');
  return sessionId;
}

module.exports = { startSession };
