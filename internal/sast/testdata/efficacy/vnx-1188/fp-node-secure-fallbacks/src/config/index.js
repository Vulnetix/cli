module.exports = {
  debug: process.env.DEBUG === 'true',
  verify: process.env.TLS_VERIFY !== 'false',
  secureCookies: process.env.SECURE_COOKIES || 'true',
  port: process.env.PORT || 3000,
  // debug: process.env.DEBUG || true,
};
