import { ApolloServer } from '@apollo/server';
import { expressMiddleware } from '@apollo/server/express4';
import type { Context } from './context';
import { typeDefs, resolvers } from './schema';

~>export const server = new ApolloServer<Context>({
  typeDefs,
  resolvers,
});

export const middleware = () => expressMiddleware(server);
