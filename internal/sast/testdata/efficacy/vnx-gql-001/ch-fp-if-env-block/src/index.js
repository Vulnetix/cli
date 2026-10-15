const express = require('express');
const { graphqlHTTP } = require('express-graphql');
const schema = require('./schema');

const app = express();

if (process.env.NODE_ENV !== 'production') {
  app.use('/graphiql', graphqlHTTP({ schema, graphiql: true }));
}

app.use('/graphql', graphqlHTTP({ schema, graphiql: false }));
