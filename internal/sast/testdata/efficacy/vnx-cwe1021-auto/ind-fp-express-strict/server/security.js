const helmet = require('helmet');

module.exports = function secure(app) {
  app.use(helmet({ frameguard: { action: 'deny' } }));
  app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('Content-Security-Policy', "default-src 'self'; frame-ancestors 'self' https://partner.example.com");
    next();
  });
};
