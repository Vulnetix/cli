const http = require('http');

function probe(req, res) {
  const opts = {
    path: '/status',
    port: 8080,
  };
~>  http.get({ host: req.query.host, path: '/latest/meta-data/' }, (upstream) => {
    res.status(200).json({ code: upstream.statusCode });
  }).on('error', () => res.status(500).end());
}

module.exports = probe;
