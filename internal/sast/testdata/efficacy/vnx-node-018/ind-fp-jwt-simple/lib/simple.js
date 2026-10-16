const jwt = require('jwt-simple');
function read(token, secret) {
  return jwt.decode(token, secret);
}
module.exports = read;
