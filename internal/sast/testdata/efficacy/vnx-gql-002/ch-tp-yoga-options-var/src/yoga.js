const { createYoga } = require('graphql-yoga');
const { schema } = require('./schema');

const options = {
  schema,
~>  batching: true,
};

module.exports = createYoga(options);
