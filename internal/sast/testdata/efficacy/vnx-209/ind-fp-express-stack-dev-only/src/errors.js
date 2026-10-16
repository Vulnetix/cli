module.exports = function errorHandler(err, req, res, next) {
  console.error(err.stack);
  res.status(err.status || 500).json({
    message: 'Something went wrong',
    stack: process.env.NODE_ENV === 'production' ? undefined : err.stack,
  });
};
