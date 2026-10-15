module.exports = function panel(req, res) {
  if (req.signedCookies.role === 'admin') {
    return res.render('panel');
  }
  return res.status(403).end();
};
