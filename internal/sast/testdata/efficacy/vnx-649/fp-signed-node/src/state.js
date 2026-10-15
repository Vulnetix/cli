const crypto = require('crypto');

function readState(req) {
  const [body, mac] = req.cookies.state.split('.');
  const expected = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  if (!crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(expected))) throw new Error('bad mac');
  return JSON.parse(Buffer.from(body, 'base64url').toString());
}
