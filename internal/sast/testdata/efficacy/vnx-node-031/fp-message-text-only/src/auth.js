const logger = require('./logger');

function login(user) {
  console.log('BEE tokens extracted successfully');
  logger.info('password changed for user %s', user.id);
  logger.error(`Could not create card: ${errorMessage(err)}`);
  console.warn("token expired, refreshing");
  logger.info({ userId: user.id, action: 'reset-password' });
}
module.exports = login;

function refreshed(user) {
  logger.info(`token refreshed for ${user.id} (secret rotation ${rotationId})`);
}
module.exports.refreshed = refreshed;
