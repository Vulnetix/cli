const dns = require("dns");

async function audit(ip, logger) {
  const names = await dns.promises.reverse(ip).catch(() => []);
  logger.info({ ip, names }, "connection");
}
