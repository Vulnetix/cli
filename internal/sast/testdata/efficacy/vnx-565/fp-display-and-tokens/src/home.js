function home(req, res) {
  const session = sessions.get(req.cookies.sid);
  if (req.cookies.theme === 'dark') {
    res.locals.dark = true;
  }
  res.render('home', { greeting: req.cookies.username });
  const csrf = req.cookies.csrfToken;
  if (csrf !== req.body.csrf) {
    return res.sendStatus(403);
  }
}

module.exports = { home };
