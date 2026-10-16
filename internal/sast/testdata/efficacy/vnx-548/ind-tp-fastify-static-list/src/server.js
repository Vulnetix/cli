const path = require('path');
const fastify = require('fastify')({ logger: true });

~>fastify.register(require('@fastify/static'), { root: path.join(__dirname, 'files'), prefix: '/files/', list: true });

fastify.listen({ port: 3000 });
