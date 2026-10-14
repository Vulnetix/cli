// X-Frame-Options cannot list several origins, so the CSP directive replaces it.
const PARTNERS = ['https://a.example.com', 'https://b.example.com'];

function framePolicy(req, res, next) {
  res.removeHeader('X-Frame-Options');
  res.setHeader('Content-Security-Policy', `frame-ancestors 'self' ${PARTNERS.join(' ')}`);
  next();
}

module.exports = { framePolicy };
