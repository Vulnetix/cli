const dns = require("dns");

function internalOnly(req, res, next) {
~>  dns.reverse(req.socket.remoteAddress, (err, hostnames) => {
    if (err) return res.sendStatus(403);
    if (hostnames.some((h) => h.endsWith(".internal.example.com"))) return next();
    res.sendStatus(403);
  });
}

module.exports = { internalOnly };
