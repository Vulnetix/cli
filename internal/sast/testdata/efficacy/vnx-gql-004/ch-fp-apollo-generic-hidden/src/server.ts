import { ApolloServer } from '@apollo/server';
import type { Context } from './context';
import { typeDefs, resolvers } from './schema';

export const server = new ApolloServer<Context>({
  typeDefs,
  resolvers,
  hideSchemaDetailsFromClientErrors: true,
});
