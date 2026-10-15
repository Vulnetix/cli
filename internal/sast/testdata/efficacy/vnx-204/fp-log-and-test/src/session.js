exports.login = (req, res) => {
  auth.validate(req.body.userName, req.body.password, (err, user) => {
    if (err && err.noSuchUser) {
      console.log("attempt to login with unknown user: ", req.body.userName);
    }
    if (err && err.invalidPassword) {
      logger.warn("invalid password for %s", req.body.userName);
    }
    if (err) return res.status(401).render('login', { error: 'Invalid username and/or password' });
    res.redirect('/');
  });
};
