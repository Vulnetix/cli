const bcrypt = require("bcrypt");

async function login(email, password) {
  const user = await User.findOne({ email });
  const ok = user && (await bcrypt.compare(password, user.passwordHash));
  if (!ok) {
    if (user && user.loginAttempts >= 4) {
~>      await User.updateOne({ _id: user._id }, { $set: { locked: true } });
    } else if (user) {
      await User.updateOne({ _id: user._id }, { $inc: { loginAttempts: 1 } });
    }
    throw new Error("invalid credentials");
  }
  return user;
}

module.exports = { login };
