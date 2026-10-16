import Fastify from 'fastify';
import { metrics } from './metrics';

const app = Fastify({ logger: true });

~>app.get('/superuser/metrics', async (request, reply) => {
  return metrics.snapshot();
});

~>app.delete(
  '/management/cache/:key',
  async (request, reply) => {
    await metrics.flush();
    reply.code(204).send();
  });

app.listen({ port: 3000 });
