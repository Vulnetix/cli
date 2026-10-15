const fastify = require('fastify')({ logger: true });

~>fastify.register(require('@fastify/cors'), { origin: '*' });

fastify.get('/api/data', async () => ({ ok: true }));
fastify.listen({ port: 3000 });
