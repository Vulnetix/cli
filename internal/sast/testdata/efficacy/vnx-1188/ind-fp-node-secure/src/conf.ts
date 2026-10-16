export const conf = {
  debug: process.env.DEBUG || 'false',
  verifyTls: process.env.VERIFY_SSL ?? 'true',
  noFallback: process.env.REQUIRE_AUTH,
  debugPort: process.env.DEBUG_PORT || '9229',
};
// const x = process.env.SKIP_TLS_VERIFY || 'true';
