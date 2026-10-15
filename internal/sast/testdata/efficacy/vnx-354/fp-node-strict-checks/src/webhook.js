const crypto = require('crypto');

function verify(req, secret) {
  const sig = req.headers['x-signature'];
  if (!sig) {
    throw new Error('missing signature');
  }
  const expected = crypto.createHmac('sha256', secret).update(req.rawBody).digest('hex');
  if (sig && sig !== expected) {
    throw new Error('bad signature');
  }
  if (!sig.startsWith('sha256=')) {
    throw new Error('bad scheme');
  }
  const digest = crypto.createHash('sha256').update(req.rawBody).digest('hex');
  const shortId = digest.slice(0, 12);
  return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
}

function route() {
  if (window.location.hash.startsWith('#/admin')) {
    return 'admin';
  }
}
