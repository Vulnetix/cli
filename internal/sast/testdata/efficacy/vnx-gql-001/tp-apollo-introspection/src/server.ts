import { ApolloServer } from '@apollo/server';
import { startStandaloneServer } from '@apollo/server/standalone';
import { typeDefs, resolvers } from './schema';

const server = new ApolloServer({
  typeDefs,
  resolvers,
~>  introspection: true,
});

const { url } = await startStandaloneServer(server, { listen: { port: 4000 } });
console.log(`ready at ${url}`);
