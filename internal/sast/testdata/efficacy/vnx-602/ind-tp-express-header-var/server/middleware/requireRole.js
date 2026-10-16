function requireRole(wanted) {
  return function (req, res, next) {
    const role = req.headers['x-user-role'];
    const tenant = req.headers['x-tenant'];
    req.tenant = tenant;
~>    if (role !== wanted) {
      return res.status(403).send('Forbidden');
    }
    next();
  };
}

module.exports = requireRole;
