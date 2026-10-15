export function loginHandler(req, res) {
  const genericMessage = 'Invalid username and/or password';
~>  const invalidUserNameMessage = 'Invalid username';
  const invalidPasswordMessage = 'Invalid password';
  auth.check(req.body.userName, req.body.password, (err) => {
    if (err && err.noSuchUser) return res.render('login', { error: invalidUserNameMessage });
    if (err && err.badPassword) return res.render('login', { error: invalidPasswordMessage });
    res.redirect('/');
  });
}
