function onError(err, req, res, next) {
  logger.error({ err }, 'request failed');
  if (process.env.NODE_ENV === 'development') {
    return res.status(500).send(err.stack);
  }
  res.status(500).json({ message: 'Something went wrong' });
}
module.exports = onError;
