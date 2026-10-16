const winston = require('winston');

const logger = winston.createLogger({
  level: 'info',
~>  silent: true,
  transports: [new winston.transports.Console()],
});
module.exports = logger;
