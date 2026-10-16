const allowedOrigins = new Set(['https://app.example.com', 'https://admin.example.com']);

module.exports = function cors(req, res, next) {
  const origin = req.get('origin');
  if (allowedOrigins.has(origin)) {
    res.set('Access-Control-Allow-Origin', origin);
  }
  if (req.path.startsWith('/api/')) {
    res.set('Vary', 'Origin');
  }
  next();
};
