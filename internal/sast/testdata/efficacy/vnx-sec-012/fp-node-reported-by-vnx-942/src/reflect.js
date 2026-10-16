module.exports = function cors(req, res, next) {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  next();
};

function cors2(req, res, next) {
  const origin = req.get('origin');
  res.set('Vary', 'Origin');
  res.set('Access-Control-Allow-Origin', origin);
  next();
}
