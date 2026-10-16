module.exports = function (app) {
  app.post('/prefs', (req, res) => {
    res.cookie('theme', req.body.theme);
    res.cookie('lang', req.body.lang, { maxAge: 900000 });
    res.cookie('XSRF-TOKEN', req.csrfToken());
    res.send('ok');
  });
  app.post('/logout', (req, res) => {
    res.clearCookie('session');
    res.redirect('/');
  });
};
