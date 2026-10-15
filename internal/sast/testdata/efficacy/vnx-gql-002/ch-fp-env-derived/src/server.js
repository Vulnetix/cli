const { ApolloServer } = require('@apollo/server');
const { typeDefs, resolvers } = require('./schema');

module.exports = new ApolloServer({
  typeDefs,
  resolvers,
  allowBatchedHttpRequests: process.env.GRAPHQL_BATCHING === 'true',
});
