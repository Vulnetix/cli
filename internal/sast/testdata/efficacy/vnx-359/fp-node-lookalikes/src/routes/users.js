const logger = require('../logger');

function audit(user) {
  console.log('passport validation required');
  logger.info('ssn field updated', { userId: user.id });
  console.log(`classname ${user.className} lesson ${user.lessonId}`);
  logger.info('dob verified', { verified: user.dobVerified });
  const ssnMasked = '***-**-' + user.ssn.slice(-4);
  logger.info('ssn', ssnMasked);
}
