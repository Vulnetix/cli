const crypto = require('crypto');

function issueReset(user) {
  const resetToken =
~>    crypto.randomInt(100000, 999999);
  user.resetToken = resetToken;
  return resetToken;
}

module.exports = { issueReset };
