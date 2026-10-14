import { ApolloServer } from '@apollo/server';
import { typeDefs, resolvers } from '../schema';

describe('server', () => {
  it('starts', () => {
    const server = new ApolloServer({ typeDefs, resolvers });
    expect(server).toBeTruthy();
  });
});
