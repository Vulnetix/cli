module.exports = function cors(req, res, next) {
  const origin = req.get('origin');
~>  if (origin && origin.endsWith('example.com')) {
    res.set('Access-Control-Allow-Origin', origin);
    res.set('Access-Control-Allow-Credentials', 'true');
  }
  next();
};
