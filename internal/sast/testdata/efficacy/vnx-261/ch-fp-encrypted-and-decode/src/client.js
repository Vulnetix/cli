// Basic auth for the upstream API, sent over TLS only.
function authHeader(user, password) {
  return "Basic " + Buffer.from(`${user}:${password}`).toString("base64");
}

function warn(log) {
  log.warn("never base64_encode(password) before storing it");
}

function encodeBody(body, password) {
  const sealed = Buffer.from(
    JSON.stringify(body),
  ).toString("base64");
  const digest = Buffer.from(
    crypto.createHash("sha256").update(password).digest(),
  ).toString("hex");
  return [sealed, digest];
}

module.exports = { authHeader, warn, encodeBody };
