const dns = require("dns");

function checkPeer(req, cb) {
~>  dns.reverse(req.socket.remoteAddress, (err, hostnames) => {
    if (err) return cb(false);
    cb(hostnames.some((h) => h.endsWith(".example.com")));
  });
}

async function isPartner(ip) {
~>  const [name] = await dns.promises.reverse(ip);
  return name === "gw.partner.example";
}
