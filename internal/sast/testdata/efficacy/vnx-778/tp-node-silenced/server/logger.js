const winston = require('winston')

const logger = winston.createLogger({
  level: 'info',
~>  silent: true,
  transports: [new winston.transports.Console()]
})

~>console.log = function () {}
~>console.error = () => {}
~>logger.silent = true

module.exports = logger
