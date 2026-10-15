const https = require("https");
const tls = require("tls");

const agent = new https.Agent({
  keepAlive: true,
~>  rejectUnauthorized: false,
});

~>process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0";

function connect(host) {
~>  return tls.connect({ host, port: 443, rejectUnauthorized : false });
}

module.exports = { agent, connect };
