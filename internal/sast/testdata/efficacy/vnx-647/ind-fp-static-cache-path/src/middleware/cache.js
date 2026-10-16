function cacheHeaders(req, res, next) {
  if (req.path.startsWith('/static')) {
    res.set('Cache-Control', 'public, max-age=31536000, immutable');
  } else if (req.path === '/health') {
    res.set('Cache-Control', 'no-store');
  }
  next();
}

module.exports = cacheHeaders;
