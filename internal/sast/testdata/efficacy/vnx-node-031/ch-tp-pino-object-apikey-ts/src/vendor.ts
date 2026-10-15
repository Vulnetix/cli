import pino from 'pino';
const log = pino();

export async function charge(config: { apiKey: string }, amount: number) {
~>  log.debug({ apiKey: config.apiKey, amount }, 'calling payment provider');
}
