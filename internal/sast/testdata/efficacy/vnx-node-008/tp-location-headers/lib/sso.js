function callback(req, res) {
~>  res.location(req.params.target);
~>  res.writeHead(302, { Location: req.query.to });
  const target = req.body.service;
~>  res.setHeader('Location', target);
  res.end();
}
module.exports = callback;
