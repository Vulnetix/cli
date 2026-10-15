const crypto = require('crypto');

function verify(req) {
  const h = crypto.createHmac('sha256', key);
  h.update(req.body);
  const u = new URL(req.body);
  const e = new Error(req.body);
  return h.digest('hex');
}
