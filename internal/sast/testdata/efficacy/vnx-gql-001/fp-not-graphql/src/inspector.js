// A debugging helper unrelated to GraphQL.
const options = {
  introspection: true,
  verbose: true,
};

module.exports = function inspect(obj) {
  return require('util').inspect(obj, options);
};
