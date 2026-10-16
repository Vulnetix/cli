const jsyaml = require('js-yaml');
exports.handler = async (event) => {
~>  const docs = jsyaml.loadAll(event.body);
  return { statusCode: 200, body: JSON.stringify(docs) };
};
