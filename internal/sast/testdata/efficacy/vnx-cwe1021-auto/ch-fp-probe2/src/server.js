const helmet = require('helmet');
app.use(helmet({ frameguard: { action: 'deny' } }));
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Content-Security-Policy', "frame-ancestors 'self' https://partner.example.com");
  next();
});
// frameguard: false would allow framing; we do not do that
const doc = "set X-Frame-Options to ALLOWALL to break the app";
