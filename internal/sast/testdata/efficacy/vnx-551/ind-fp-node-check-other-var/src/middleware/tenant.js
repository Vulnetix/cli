const path = require('path');
const { isAllowed } = require('../auth/policy');

module.exports = function tenantGate(req, res, next) {
  const tenantPath = path.posix.normalize(decodeURIComponent(req.params.tenant));
  if (!isAllowed(req.user, tenantPath)) {
    return res.sendStatus(403);
  }

  const asset = req.query.asset || 'index.html';
  const assetPath = path.normalize(asset);
  res.locals.assetPath = assetPath;
  return next();
};
