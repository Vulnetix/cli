function createSession(res, userId) {
~>  const sessionId = `${Date.now().toString(36)}${process.pid.toString(36)}`;
  sessions.set(sessionId, { userId, created: Date.now() });
  res.cookie('sid', sessionId, { httpOnly: true, secure: true });
}

module.exports = { createSession };
