module.exports = function requireApiKey(req, res, next) {
~>  if (req.headers['x-api-key']) {
    return next();
  }
  res.status(401).json({ error: 'unauthorised' });
};

function requireBearer(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
~>  if (token) return next();
  return res.sendStatus(401);
}

module.exports.requireBearer = requireBearer;
