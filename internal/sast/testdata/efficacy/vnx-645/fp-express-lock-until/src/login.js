const LOCK_TIME = 15 * 60 * 1000;

async function login(req, res) {
  const user = await User.findOne({ email: req.body.email });
  if (!(await user.comparePassword(req.body.password))) {
    user.loginAttempts += 1;
    if (user.loginAttempts >= 5) {
      user.locked = true;
      user.lockUntil = Date.now() + LOCK_TIME;
    }
    await user.save();
    return res.sendStatus(401);
  }
}
