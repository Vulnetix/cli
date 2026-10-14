module.exports = function prefs(req, res) {
  res.cookie('theme', req.body.theme, { maxAge: 31536000000 });
  res.cookie('lang', 'en');
  res.cookie('XSRF-TOKEN', req.csrfToken());
  res.cookie('remember', 1, { maxAge: 60000 });
  res.end();
};
