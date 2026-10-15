function login(req, res) {
~>  const sessionId = Date.now().toString(36);
~>  res.cookie('sid', String(Date.now()), { httpOnly: true });
  return sessionId;
}

function issueToken(req) {
~>  return Buffer.from(`${req.ip}:${Date.now()}`).toString('base64');
}

module.exports = { login, issueToken };
