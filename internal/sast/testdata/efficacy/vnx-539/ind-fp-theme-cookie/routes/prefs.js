module.exports = function prefs(app) {
  app.post('/prefs/theme', (req, res) => {
    res.cookie('theme', req.body.theme, { maxAge: 365 * 24 * 60 * 60 * 1000 });
    res.cookie('lang', req.body.lang, { maxAge: 365 * 24 * 60 * 60 * 1000 });
    res.sendStatus(204);
  });
};
