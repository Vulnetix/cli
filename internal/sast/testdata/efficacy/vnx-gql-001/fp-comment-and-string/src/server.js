const { ApolloServer } = require('apollo-server');
const { typeDefs, resolvers } = require('./schema');

// Never ship with introspection: true in production.
/*
 * graphiql: true is only for local development.
 */
const warning = "do not set introspection: true outside development";

const server = new ApolloServer({ typeDefs, resolvers });
server.listen().then(() => console.log(warning));
