const logger = require('./logger')

console.log(process.env.NODE_ENV)
logger.info(`listening on ${process.env.PORT}`)
logger.info('mode', process.env['APP_MODE'])
const env = process.env
