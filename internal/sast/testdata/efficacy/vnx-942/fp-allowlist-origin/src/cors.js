const cors = require('cors');

const ALLOWED = new Set(['https://app.example.com', 'https://admin.example.com']);

function corsMiddleware(req, res, next) {
  const origin = req.headers.origin;
  if (ALLOWED.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  next();
}

const corsForApi = cors({
  origin: ['https://app.example.com'],
  credentials: true,
});

const corsDynamic = cors({
  origin: (origin, cb) => cb(null, ALLOWED.has(origin)),
});

module.exports = { corsMiddleware, corsForApi, corsDynamic };
