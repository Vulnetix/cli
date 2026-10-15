const JWT = require("jsonwebtoken");

exports.handler = async (event) => {
  const raw = event.headers.Authorization.slice(7);
~>  const claims = JWT.decode(raw);
  return { statusCode: 200, body: JSON.stringify({ tenant: claims.tenant }) };
};
