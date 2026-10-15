const bcrypt = require('bcrypt');

async function login(req, res) {
  const user = await User.findOne({ email: req.body.email });
  if (user && await bcrypt.compare(req.body.password, user.passwordHash)) {
    return res.redirect('/');
  }
  const ok = await bcrypt.compare(req.body.password, user.passwordHash);
  bcrypt.compare(req.body.password, user.passwordHash, function (err, same) {
    if (same) res.redirect('/');
  });
  bcrypt.compare(req.body.password, user.passwordHash).then((same) => {
    if (same) res.redirect('/');
  });
  if (bcrypt.compareSync(req.body.password, user.passwordHash)) {
    res.redirect('/');
  }
}

function checkPassword(user, password) {
  return bcrypt.compare(password, user.hash);
}

async function register(email, password) {
  const hash = await bcrypt.hash(password, 10);
  return User.create({ email, hash });
}
