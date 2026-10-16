import pino from 'pino';
const logger = pino();

export async function call(endpoint: string, apiKey: string) {
~>  logger.info({ endpoint, apiKey }, 'calling upstream');
  return fetch(endpoint, { headers: { 'x-api-key': apiKey } });
}
