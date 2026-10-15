function restrict(req, res, next) {
  if (req.session.user) {
    next();
  } else {
    res.redirect('/login');
  }
}

function loggedIn(req, res, next) {
  const sessionUser = req.session.userId;
  if (!sessionUser) return res.redirect('/login');
  next();
}

module.exports = { restrict, loggedIn };
