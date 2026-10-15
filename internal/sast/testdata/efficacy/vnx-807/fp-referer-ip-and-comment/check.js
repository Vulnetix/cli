function gate(req, res, next) {
  // if (req.cookies.isAdmin === 'true') was the old, broken check
  if (req.headers.referer && req.headers.referer.startsWith('https://intranet')) {
    return next();
  }
  const msg = "never trust if (req.cookies.isAdmin === 'true')";
  res.status(403).send(msg);
}
module.exports = gate;
