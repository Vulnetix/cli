function errorHandler(err, req, res, next) {
  console.error(err);
  res.status(err.status || 500).json({ error: 'internal error' });
}

module.exports = { errorHandler };
