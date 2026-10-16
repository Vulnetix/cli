const ALLOWED = new Set(['https://app.example.com', 'https://admin.example.com']);

module.exports = function cors(req, res, next) {
  const origin = req.headers.origin;
  if (origin && ALLOWED.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  next();
};

function cors2(req, res, next) {
  const origin = req.get('origin');
  res.setHeader('Access-Control-Allow-Origin', allowedOrigins.includes(origin) ? origin : 'https://app.example.com');
  next();
}
