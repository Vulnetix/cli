const yaml = require('js-yaml');
const fs = require('fs');
const path = require('path');
module.exports = function (req) {
  const file = path.join(__dirname, 'conf', 'defaults.yml');
  return yaml.load(fs.readFileSync(file, 'utf8'));
};
