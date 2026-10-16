function requireStaff(req, res, next) {
  // A decision on a privilege cookie: VNX-784 reports it.
  if (req.cookies.role === 'staff') {
    return next();
  }
  return res.sendStatus(403);
}

module.exports = { requireStaff };
