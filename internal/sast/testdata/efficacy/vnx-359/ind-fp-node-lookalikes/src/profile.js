const logger = require('./logger');

function logProfile(user) {
  console.log('dobVerified', user.dobVerified);
  logger.info({ userId: user.id, ssnLast4: user.ssn.slice(-4) }, 'profile loaded');
  logger.info('Collecting SSN for user %s', user.id);
  logger.debug({ hasNationalId: Boolean(user.nationalId) }, 'identity check');
}

module.exports = { logProfile };
