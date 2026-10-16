const http = require('http');

function forward(req, res, upstream) {
  const headers = { ...req.headers };
  headers['x-forwarded-for'] = req.socket.remoteAddress;
  res.setHeader('X-Forwarded-For', req.socket.remoteAddress);
  const out = http.request({ host: upstream, path: req.url, headers }, (r) => r.pipe(res));
  req.pipe(out);
}

module.exports = { forward };
