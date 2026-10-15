const logger = require('./logger')

~>console.log(process.env)
~>logger.info(`config: ${JSON.stringify(process.env)}`)
~>logger.debug('environment', process.env)

module.exports = {}
