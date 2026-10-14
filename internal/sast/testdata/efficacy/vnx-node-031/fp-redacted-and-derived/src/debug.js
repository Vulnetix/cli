const logger = require('./logger');

function trace(token, password, secret) {
  logger.debug('token length', token.length);
  console.log('has password:', !!password);
  logger.info({ secret: redact(secret) });
  console.log('token present', Boolean(token));
  console.log('auth type', typeof token);
  logger.info('fingerprint', sha256(password));
  logger.info('token', mask(token));
}
module.exports = trace;

function obtained(data) {
  console.log("JWT obtained:", data.token.substring(0, 8) + "...");
  console.log(`refresh prefix ${data.refreshToken.slice(0, 6)}`);
}
module.exports.obtained = obtained;
