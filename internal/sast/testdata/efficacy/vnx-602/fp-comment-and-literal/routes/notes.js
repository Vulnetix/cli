// Never do this: if (req.body.isAdmin) { ... }
const WARNING = "if (req.cookies.role === 'admin') trusts the client";

function explain(log) {
  log.warn("req.query.role === 'admin' is client-controlled");
}

module.exports = { WARNING, explain };
