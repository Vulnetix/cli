const https = require('https');

exports.probe = (req, res) => {
~>  const r = https.request({ hostname: req.body.host, path: '/', method: 'HEAD' }, (up) => {
    res.json({ status: up.statusCode });
  });
  r.end();
};
