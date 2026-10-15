async function createUser(email) {
  const user = { email, mfaEnabled: false, otpSecret: null };
  user.twoFactorEnabled = false;
  return db.users.insert(user);
}
module.exports = { createUser };
