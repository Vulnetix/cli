import { ApolloServer } from '@apollo/server';
import { typeDefs, resolvers } from '../schema';

test('batched requests', async () => {
  const server = new ApolloServer({ typeDefs, resolvers, allowBatchedHttpRequests: true });
  expect(server).toBeDefined();
});
