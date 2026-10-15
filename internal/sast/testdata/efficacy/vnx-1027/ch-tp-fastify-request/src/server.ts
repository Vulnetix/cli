import Fastify from 'fastify';

const app = Fastify();

app.get('/report/:kind', async (request, reply) => {
  const { kind } = request.params as { kind: string };
~>  const builder = require(`./reports/${kind}`);
  return builder.build();
});

app.post('/hook', async (request) => {
~>  const handler = await import('./hooks/' + (request.body as any).event);
  return handler.run();
});
