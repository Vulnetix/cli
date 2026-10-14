import { ApolloServer } from '@apollo/server';
import { typeDefs, resolvers } from './schema';

export const server = new ApolloServer({
  typeDefs,
  resolvers,
~>  allowBatchedHttpRequests:   true,
});
~>export const admin = new ApolloServer({ typeDefs, resolvers, 'allowBatchedHttpRequests': true });
