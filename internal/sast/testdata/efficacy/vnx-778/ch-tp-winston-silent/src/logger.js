const winston = require("winston");

module.exports = winston.createLogger({
  level: "info",
~>  silent: true,
  transports: [new winston.transports.Console()],
});
