const crypto = require('crypto');

function verifyPartner(req) {
  const sig = req.get('X-Partner-Signature');
  if (!sig) return false;
  const digest = crypto.createHmac('sha256', process.env.PARTNER_KEY).update(req.body).digest('hex');
  const a = Buffer.from(sig, 'hex');
  const b = Buffer.from(digest, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function nextToken(lexer) {
  const token = lexer.peek();
  if (token.type === TokenType.STRING) return lexer.next();
  return null;
}

module.exports = { verifyPartner, nextToken };
