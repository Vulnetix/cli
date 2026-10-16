const winston = require('winston');

function issue(userId, sessionToken) {
~>  winston.info(`login ok for ${userId} with session ${sessionToken}`);
}
function trace(req) {
~>  console.debug('headers', req.headers.authorization);
}
module.exports = { issue, trace };
