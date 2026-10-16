const logger = require('./logger');

function changed(user) {
  logger.info('password changed for user %s', user.id);
  console.log('Please enter your API key in the settings page');
  logger.warn('token expired for session owner ' + user.id);
}
module.exports = changed;
