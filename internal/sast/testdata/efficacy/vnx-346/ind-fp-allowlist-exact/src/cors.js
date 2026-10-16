const ALLOWED_ORIGINS = new Set(["https://app.acme.com", "https://admin.acme.com"]);
const allowedOrigins = ["https://partner.acme.com"];

function corsOrigin(origin, callback) {
  if (!origin || ALLOWED_ORIGINS.has(origin) || allowedOrigins.includes(origin)) {
    return callback(null, true);
  }
  if (origin === "https://legacy.acme.com") return callback(null, true);
  return callback(new Error("blocked"));
}

module.exports = { corsOrigin };
