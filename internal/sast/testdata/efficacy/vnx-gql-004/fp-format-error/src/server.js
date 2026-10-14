const { ApolloServer } = require('apollo-server-express');
const { typeDefs, resolvers } = require('./schema');

const server = new ApolloServer({
  typeDefs,
  resolvers,
  formatError: (err) => {
    if (/Did you mean/.test(err.message)) {
      return { message: 'Invalid query' };
    }
    return err;
  },
});
module.exports = server;
