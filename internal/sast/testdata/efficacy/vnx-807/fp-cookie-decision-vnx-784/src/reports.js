function listReports(req, res) {
  // A decision on a privilege cookie: VNX-784 reports it.
  if (req.cookies.isAdmin === 'true') {
    return res.json(allReports());
  }
  return res.json(ownReports(req.user));
}

module.exports = { listReports };
