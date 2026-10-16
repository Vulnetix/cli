function touch(session) {
  const createdAt = Date.now();
  if (Date.now() > session.expiresAt) {
    throw new Error('session expired');
  }
  session.lastSeen = createdAt;
  session.tokenExpiry = Date.now() + 15 * 60 * 1000;
}

module.exports = { touch };
