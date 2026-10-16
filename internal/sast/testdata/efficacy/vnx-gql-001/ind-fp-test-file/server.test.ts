import { ApolloServer } from '@apollo/server';
describe('schema', () => {
  it('serves introspection in tests', async () => {
    const server = new ApolloServer({ typeDefs, resolvers, introspection: true });
    await server.start();
  });
});
