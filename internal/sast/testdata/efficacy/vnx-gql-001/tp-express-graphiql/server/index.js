const express = require('express');
const { graphqlHTTP } = require('express-graphql');
const schema = require('./schema');

const app = express();
app.use('/graphql', graphqlHTTP({
  schema: schema,
~>  graphiql:true
}));
~>app.use('/v2/graphql', graphqlHTTP({ schema, rootValue: {}, graphiql: true }));
app.listen(3000);
