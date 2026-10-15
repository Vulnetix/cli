const logger = require("./logger");

function startSession(user, token) {
  const encodedToken = Buffer.from(token, "utf8").toString("base64");
~>  logger.info("session started for %s with %s", user.id, encodedToken);
  return { user, encodedToken };
}

module.exports = { startSession };
