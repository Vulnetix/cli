const yaml = require('js-yaml');
function parse(input) {
~>  return yaml.load(input, { schema: yaml.DEFAULT_FULL_SCHEMA });
}
module.exports = parse;
