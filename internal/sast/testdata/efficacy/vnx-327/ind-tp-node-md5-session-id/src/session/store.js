const crypto = require('crypto');

class SessionStore {
  constructor(redis) {
    this.redis = redis;
  }

  async create(req, userId) {
~>    const sessionId = crypto.createHash('md5').update(`${userId}:${Date.now()}:${req.ip}`).digest('hex');
    await this.redis.set(`sess:${sessionId}`, JSON.stringify({ userId }), 'EX', 3600);
    return sessionId;
  }
}

module.exports = SessionStore;
