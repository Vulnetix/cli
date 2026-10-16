async function deactivateUser(adminUser, target) {
  if (!adminUser.isAdmin) throw new Error('forbidden');
  target.active = false;
  await target.save();
}
async function onBad(user) {
  user.loginAttempts += 1;
  if (user.loginAttempts > 5) {
    user.lockUntil = Date.now() + LOCK_TIME;
  }
}
