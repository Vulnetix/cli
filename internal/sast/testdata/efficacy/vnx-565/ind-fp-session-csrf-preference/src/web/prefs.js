function preferences(req, res) {
  const sid = req.cookies.sessionId;
  const theme = req.cookies.theme || 'light';
  const lang = req.cookies.locale;
  res.cookie('theme', theme, { maxAge: 31536000000 });
  res.render('prefs', { sid: Boolean(sid), theme, lang });
}

module.exports = preferences;
