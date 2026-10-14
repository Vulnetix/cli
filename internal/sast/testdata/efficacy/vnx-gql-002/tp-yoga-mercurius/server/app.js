import { createServer } from 'node:http';
import { createYoga } from 'graphql-yoga';
import Fastify from 'fastify';
import mercurius from 'mercurius';
import { schema, resolvers } from './schema.js';

const yoga = createYoga({
  schema,
~>  batching: true,
});
createServer(yoga).listen(4000);

const app = Fastify();
app.register(mercurius, {
  schema,
  resolvers,
~>  allowBatchedQueries: true,
});
