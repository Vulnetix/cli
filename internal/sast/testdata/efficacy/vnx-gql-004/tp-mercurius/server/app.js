const Fastify = require('fastify');
const mercurius = require('mercurius');
const { schema, resolvers } = require('./schema');

const app = Fastify();
~>app.register(mercurius, {
  schema,
  resolvers,
});
app.listen({ port: 3000 });
