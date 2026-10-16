const LOCK_TIME = 15 * 60 * 1000;
const MAX_ATTEMPTS = 5;

async function registerFailure(user) {
  user.loginAttempts += 1;
  if (user.loginAttempts >= MAX_ATTEMPTS) {
    user.locked = true;
    user.lockUntil = Date.now() + LOCK_TIME;
  }
  await user.save();
}

function isLocked(user) {
  return Boolean(user.lockUntil && user.lockUntil > Date.now());
}

module.exports = { registerFailure, isLocked };
