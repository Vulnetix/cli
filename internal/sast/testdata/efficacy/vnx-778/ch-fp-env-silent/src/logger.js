const winston = require("winston");

module.exports = winston.createLogger({
  level: "info",
  silent: process.env.NODE_ENV === "test",
  transports: [new winston.transports.Console()],
});
