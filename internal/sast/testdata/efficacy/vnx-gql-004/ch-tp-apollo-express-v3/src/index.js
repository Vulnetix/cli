const express = require('express');
const { ApolloServer, gql } = require('apollo-server-express');

const typeDefs = gql`type Query { hello: String }`;
const resolvers = { Query: { hello: () => 'world' } };

async function start() {
~>  const apollo = new ApolloServer(
    { typeDefs, resolvers, introspection: false },
  );
  await apollo.start();
  const app = express();
  apollo.applyMiddleware({ app });
  app.listen(4000);
}

start();
