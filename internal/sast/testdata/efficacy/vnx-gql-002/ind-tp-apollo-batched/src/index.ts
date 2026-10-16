import { ApolloServer } from 'apollo-server-express';

const server = new ApolloServer({
  schema,
  context,
~>  allowBatchedHttpRequests: true,
});
