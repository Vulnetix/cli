const { exec } = require('child_process');

function lookup(req, res) {
  const domain = req.query.domain;
~>  exec(`nslookup ${domain}`, (err, stdout) => {
    if (err) return res.status(500).end();
    res.type('text/plain').send(stdout);
  });
}

module.exports = { lookup };
