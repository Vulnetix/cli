module.exports = {
  session: { secret: process.env.SESSION_SECRET || 'dev-only-fallback' },
  hmac: process.env.HMAC_KEY || 'dev',
};
