import { ApolloServer } from '@apollo/server';
import { typeDefs, resolvers } from './schema';

const exposeSchema = process.env.GRAPHQL_EXPOSE_SCHEMA === '1';

export const server = new ApolloServer({
  typeDefs,
  resolvers,
  ...(exposeSchema ? { introspection: true } : {}),
});
