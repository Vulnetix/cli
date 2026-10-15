function cors(req, res, next) {
  const origin = req.headers.origin || '';
~>  if (origin.endsWith('example.com')) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  next();
}
