const debug = require('debug')('app:auth');

function verify(token) {
~>  debug('verifying token %s', token);
  return jwt.verify(token, key);
}
