let lastResetCode = 500000;

function beginReset(user) {
~>  lastResetCode++;
  user.resetCode = String(lastResetCode);
  return mailer.sendReset(user.email, user.resetCode);
}

module.exports = { beginReset };
