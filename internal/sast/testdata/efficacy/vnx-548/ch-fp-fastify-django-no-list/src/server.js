const path = require('node:path');
const fastify = require('fastify')();

fastify.register(require('@fastify/static'), {
  root: path.join(__dirname, 'public'),
  list: false,
});

const options = { list: true };
fastify.get('/todos', async () => options);

fastify.listen({ port: 3000 });
