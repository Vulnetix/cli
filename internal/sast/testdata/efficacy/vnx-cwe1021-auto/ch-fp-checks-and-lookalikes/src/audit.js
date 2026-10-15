// Audits a response for weak framing headers; it never sets them.
function auditFraming(res) {
  const xfo = res.headers['x-frame-options'];
  if (xfo === 'ALLOWALL' || xfo === 'ALLOW-FROM') {
    return { weak: true, message: "X-Frame-Options ALLOWALL lets any site frame the page" };
  }
  if (res.headers['x-frame-options'] == 'allow-from') {
    return { weak: true };
  }
  return { weak: false };
}

const helmet = require('helmet');
const app = require('express')();
app.use(helmet({ frameguard: { action: 'deny' } }));
app.use(helmet.contentSecurityPolicy({
  directives: { frameAncestors: ["'self'", 'https://*.partner.example'] },
}));
app.use((req, res, next) => {
  res.removeHeader('X-Powered-By');
  res.setHeader('Content-Security-Policy', "frame-ancestors 'none'");
  next();
});

module.exports = { auditFraming };
