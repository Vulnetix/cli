const crypto = require('crypto');

module.exports = function verify(req, res, next) {
  const sig = req.headers['x-hub-signature-256'];
  if (!sig) {
    return res.status(401).json({ error: 'signature required' });
  }
  const expected = 'sha256=' + crypto.createHmac('sha256', process.env.SECRET).update(req.rawBody).digest('hex');
  if (sig && (sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected)))) {
    return res.status(401).json({ error: 'bad signature' });
  }
  next();
};
