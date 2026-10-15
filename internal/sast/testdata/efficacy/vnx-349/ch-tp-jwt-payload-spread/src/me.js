const jwt = require("jsonwebtoken");

function currentContext(req) {
  const token = req.headers.authorization.slice(7);
  const payload = jwt.verify(token, process.env.JWT_PUBLIC_KEY, { algorithms: ["RS256"] });
~>  const identity = { ...payload, ...req.query };
  return identity;
}

module.exports = { currentContext };
