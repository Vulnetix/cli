import { ApolloServer } from '@apollo/server';
import { typeDefs, resolvers } from './schema';

export function buildServer() {
  return new ApolloServer({
    typeDefs,
    resolvers,
~>    introspection: true,
    csrfPrevention: true,
  });
}
