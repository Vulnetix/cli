const { ApolloServer } = require('@apollo/server');
const { typeDefs, resolvers } = require('./schema');

const isProduction = process.env.NODE_ENV === 'production';

const server = new ApolloServer({
  typeDefs,
  resolvers,
~>  introspection: true, includeStacktraceInErrorResponses: !isProduction,
});

module.exports = server;
