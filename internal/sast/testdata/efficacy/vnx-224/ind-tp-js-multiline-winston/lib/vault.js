const winston = require("winston");
const logger = winston.createLogger({ transports: [new winston.transports.Console()] });

async function unseal(vaultUrl, unsealKey, apiToken) {
~>  logger.info("unseal request",
    vaultUrl,
    Buffer.from(apiToken).toString("base64")
  );
  return fetch(`${vaultUrl}/v1/sys/unseal`, { method: "PUT", body: JSON.stringify({ key: unsealKey }) });
}

module.exports = { unseal };
