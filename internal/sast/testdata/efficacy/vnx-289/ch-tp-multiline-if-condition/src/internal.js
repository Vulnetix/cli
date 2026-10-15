module.exports = function internalOnly(req, res, next) {
  if (
~>    req.originalUrl.startsWith('/internal/') &&
    !req.headers['x-internal-token']
  ) {
    return res.sendStatus(403);
  }
  return next();
};
