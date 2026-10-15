function prefs (req, res, options) {
  res.cookie('theme', 'dark')
  res.cookie('lang', req.query.lang, { maxAge: 900000 })
  res.cookie('token', req.token, options)
  document.cookie = "theme=" + theme + "; path=/";
}

function remember (req, res) {
  res.cookie('remember', 1, { maxAge: 60000 })
}
