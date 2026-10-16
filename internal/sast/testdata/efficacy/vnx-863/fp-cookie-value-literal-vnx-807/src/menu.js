function menu(req, res) {
  const kind = req.cookies.kind;
  // A cookie value compared with a privileged literal: VNX-807 reports it.
  if (kind === 'administrator') {
    return res.render('menu-full');
  }
  return res.render('menu');
}

module.exports = { menu };
