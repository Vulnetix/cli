const ALLOWED = new Set(['https://app.example.com', 'https://admin.example.com']);

function cors(req, res, next) {
  const origin = req.headers.origin || '';
  if (ALLOWED.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  next();
}

function isCompanyHost(host) {
  return host === 'example.com' || host.endsWith('.example.com');
}

function isCompanyEmail(email) {
  return email.endsWith('@example.com');
}

function isImage(filename) {
  return filename.endsWith('.png');
}
