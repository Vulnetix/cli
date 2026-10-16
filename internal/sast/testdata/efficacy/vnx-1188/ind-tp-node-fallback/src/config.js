const cfg = {
~>  skipTlsVerify: process.env.SKIP_TLS_VERIFY || 'true',
  port: process.env.PORT || 3000,
};
~>const secureCookies = process.env.COOKIE_SECURE === 'true';
module.exports = cfg;
