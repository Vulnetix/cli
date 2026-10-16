function forward(req, res) {
  req.headers['x-forwarded-for'] = req.query.ip;
  res.writeHead(200, { 'Content-Type': 'application/json', 'X-Version': '2' });
  res.end('{}');
}
