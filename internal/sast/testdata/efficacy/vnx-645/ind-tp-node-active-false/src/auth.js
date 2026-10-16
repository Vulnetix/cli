async function onBadPassword(user) {
  user.loginAttempts += 1;
  if (user.loginAttempts > 5) {
~>    user.active = false;
  }
  await user.save();
}
