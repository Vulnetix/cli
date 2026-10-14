const pino = require('pino');
const logger = pino();

async function callApi(apiKey, endpoint) {
~>  logger.info({ endpoint, apiKey }, 'calling upstream');
  const { access_token: accessToken } = await exchange();
~>  logger.debug('received token ' + accessToken);
  return accessToken;
}
module.exports = callApi;
