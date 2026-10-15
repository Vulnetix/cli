function home(req, res) {
  res.render('home', { name: req.cookies.username });
}

module.exports = { home };
