import { ApolloServer } from '@apollo/server';
import { typeDefs, resolvers } from './schema';

export const server = new ApolloServer({
  typeDefs,
  resolvers,
  hideSchemaDetailsFromClientErrors: true,
});
