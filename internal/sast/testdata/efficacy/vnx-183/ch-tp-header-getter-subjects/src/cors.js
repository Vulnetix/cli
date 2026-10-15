function cors(req, res, next) {
~>  if (req.get('origin').includes('acme.com')) {
    res.setHeader('Access-Control-Allow-Origin', req.get('origin'));
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  next();
}

module.exports = cors;
