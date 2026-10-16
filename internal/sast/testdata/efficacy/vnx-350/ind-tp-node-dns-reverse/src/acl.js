const dns = require("dns");

function allowPartner(req, res, next) {
~>  dns.reverse(req.socket.remoteAddress, (err, hostnames) => {
    if (err) return res.sendStatus(403);
    if (hostnames.some((h) => h.endsWith(".partner.example.org"))) return next();
    res.sendStatus(403);
  });
}

module.exports = allowPartner;
