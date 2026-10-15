module.exports = function errorHandler(err, req, res, next) {
  res.status(err.status || 500).json({ error: 'request failed' });
};
