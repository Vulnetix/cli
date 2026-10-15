const crypto = require('crypto');

function verifyStripe(req, secret) {
  const sig = req.headers['x-signature'];
  const expected = crypto.createHmac('sha256', secret).update(req.rawBody).digest('hex');
~>  if (sig && sig !== expected) {
    throw new Error('bad signature');
  }
  return true;
}

function verifyBuffer(req, secret) {
  const signature = Buffer.from(req.get('x-hub-signature') || '', 'utf8');
  const mac = Buffer.from(crypto.createHmac('sha256', secret).update(req.rawBody).digest('hex'));
~>  if (signature.length && !crypto.timingSafeEqual(signature, mac)) {
    return false;
  }
  return true;
}

function verifyFile(buf, provided) {
  const digest = crypto.createHash('sha256').update(buf).digest('hex');
~>  return digest.includes(provided);
}

function verifyPrefix(buf, provided) {
  const hash = crypto.createHash('sha256').update(buf).digest('hex');
~>  return hash.slice(0, 8) === provided;
}
