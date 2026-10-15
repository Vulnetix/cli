import { createYoga, createSchema } from 'graphql-yoga';
import type { ServerContext } from './types';

~>export const yoga = createYoga<ServerContext>({
  schema: createSchema({ typeDefs: `type Query { ping: String }`, resolvers: {} }),
  maskedErrors: true,
});
