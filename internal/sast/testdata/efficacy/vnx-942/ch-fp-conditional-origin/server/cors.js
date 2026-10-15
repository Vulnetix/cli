const ALLOWED = ['https://app.example.com', 'https://admin.example.com'];

module.exports = function corsMiddleware(req, res, next) {
  const origin = req.headers.origin;
  if (ALLOWED.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  next();
};
