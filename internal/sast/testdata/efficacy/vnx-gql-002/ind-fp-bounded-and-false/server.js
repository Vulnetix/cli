const a = new ApolloServer({ schema, allowBatchedHttpRequests: false });
const b = createYoga({ schema, batching: { limit: 5 } });
const c = new ApolloServer({ schema, allowBatchedHttpRequests: process.env.ALLOW_BATCH === '1' });
fastify.register(mercurius, { schema, allowBatchedQueries: false });
