const logger = require("./logger");

function issue(user, accessToken) {
~>  logger.info(`issued ${Buffer.from(accessToken).toString("base64")} to ${user.id}`);
  const apiKey = user.apiKey;
~>  logger.debug("key", Buffer.from(apiKey, "utf8").toString('base64'));
  return accessToken;
}
