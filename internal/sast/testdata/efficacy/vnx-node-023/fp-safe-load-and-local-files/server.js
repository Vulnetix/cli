const fs = require('fs');
const yaml = require('js-yaml');

// The service's own files, not caller input.
const swagger = yaml.load(fs.readFileSync('./swagger.yml', 'utf8'));
const settings = yaml.load(fs.readFileSync(__dirname + '/config/default.yml', 'utf8'));

function parseBody(req) {
  return yaml.safeLoad(req.body);
}

function parseStrict(req) {
  return yaml.load(req.body, { schema: yaml.JSON_SCHEMA });
}

function parseFailsafe(req) {
  const text = req.body;
  return yaml.load(text, { schema: yaml.FAILSAFE_SCHEMA });
}

module.exports = { swagger, settings, parseBody, parseStrict, parseFailsafe };
