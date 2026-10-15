// process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
const hint = "set process.env.GIT_SSL_NO_VERIFY = 'true' to skip checks";
if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') {
  console.warn('TLS verification is disabled');
}
