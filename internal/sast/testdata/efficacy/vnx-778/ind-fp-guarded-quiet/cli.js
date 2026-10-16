const winston = require('winston');
const logger = winston.createLogger({ transports: [new winston.transports.Console()] });
if (process.env.QUIET) {
  logger.silent = true;
}
module.exports = logger;
