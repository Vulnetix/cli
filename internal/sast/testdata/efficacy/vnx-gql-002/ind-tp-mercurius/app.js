const fastify = require('fastify')();
const mercurius = require('mercurius');
fastify.register(mercurius, {
  schema,
  resolvers,
~>  allowBatchedQueries: true,
});
