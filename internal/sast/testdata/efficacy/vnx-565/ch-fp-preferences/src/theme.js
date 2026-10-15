function theme(req, res) {
  const theme = req.cookies.theme;
  if (theme === 'dark') {
    res.locals.dark = true;
  }
  if (req.cookies.lang === 'de') res.locals.lang = 'de';
}
