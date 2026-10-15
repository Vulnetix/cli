async function loadSession(sessionToken) {
  const s = await store.get(sessionToken);
  if (!s) {
~>    throw new Error(`No session for token ${sessionToken}`);
  }
  return s;
}

function checkSecret(req, res, next) {
  const secret = req.headers['x-webhook-secret'];
  if (secret !== process.env.WEBHOOK_SECRET) {
~>    return res.status(403).json({ error: 'secret mismatch: ' + secret });
  }
  next();
}

function verify(password, cb) {
  if (!password) return cb(null, false);
~>  cb(new Error('cannot hash password ' + password));
}

module.exports = { loadSession, checkSecret, verify };
