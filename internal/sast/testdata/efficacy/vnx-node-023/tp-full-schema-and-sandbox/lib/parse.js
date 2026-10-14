const yaml = require('js-yaml');
const vm = require('vm');
const fs = require('fs');

function readTemplate(path) {
  const text = fs.readFileSync(path, 'utf8');
~>  return yaml.load(text, { schema: yaml.DEFAULT_FULL_SCHEMA });
}

function preview({ file }) {
  const data = file.buffer.toString();
  const sandbox = { yaml, data };
  vm.createContext(sandbox);
~>  return vm.runInContext('JSON.stringify(yaml.load(data))', sandbox, { timeout: 2000 });
}

module.exports = { readTemplate, preview };
