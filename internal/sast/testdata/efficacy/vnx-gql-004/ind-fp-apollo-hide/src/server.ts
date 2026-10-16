import { ApolloServer } from '@apollo/server';
const server = new ApolloServer({
  typeDefs,
  resolvers,
  hideSchemaDetailsFromClientErrors: true,
});
