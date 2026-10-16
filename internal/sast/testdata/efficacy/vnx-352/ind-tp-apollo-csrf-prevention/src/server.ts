import { ApolloServer } from '@apollo/server';
import { expressMiddleware } from '@apollo/server/express4';
import express from 'express';
import { typeDefs, resolvers } from './schema';

const app = express();

const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production',
~>  csrfPrevention: false,
});

await server.start();
app.use('/graphql', express.json(), expressMiddleware(server));
app.listen(4000);
