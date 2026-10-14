import { ApolloServer } from '@apollo/server';
import { typeDefs, resolvers } from '../schema';

it('answers the introspection query', async () => {
  const server = new ApolloServer({ typeDefs, resolvers, introspection: true });
  const res = await server.executeOperation({ query: '{ __schema { types { name } } }' });
  expect(res.body).toBeDefined();
});
