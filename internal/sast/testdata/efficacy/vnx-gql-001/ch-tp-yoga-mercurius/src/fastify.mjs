import Fastify from 'fastify';
import mercurius from 'mercurius';
import { schema, resolvers } from './graph.mjs';

const app = Fastify();
app.register(mercurius, {
  schema,
  resolvers,
~>  graphiql: true
});
