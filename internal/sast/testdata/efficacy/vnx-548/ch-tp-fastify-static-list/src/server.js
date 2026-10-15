const path = require('node:path');
const fastify = require('fastify')({ logger: true });

fastify.register(require('@fastify/static'), {
  root: path.join(__dirname, 'uploads'),
  prefix: '/uploads/',
~>  list: true,
});

fastify.listen({ port: 3000 });
