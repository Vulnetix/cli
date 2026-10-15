const MAX_FAILED = 5;

async function recordFailure(user) {
  user.failedLoginAttempts += 1;
  if (user.failedLoginAttempts >= MAX_FAILED) {
    user.lockedUntil = Date.now() + 15 * 60 * 1000;
  }
  await user.save();
}
module.exports = { recordFailure };
