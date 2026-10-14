import { ApolloServer } from '@apollo/server';
import { expressMiddleware } from '@apollo/server/express4';
import { typeDefs, resolvers } from './schema';

~>const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: false,
});
await server.start();
export const graphql = expressMiddleware(server);
