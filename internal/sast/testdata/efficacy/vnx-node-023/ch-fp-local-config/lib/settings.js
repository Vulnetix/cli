const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const file = path.join(__dirname, '..', 'config', 'settings.yml');
const settings = yaml.load(fs.readFileSync(file, 'utf8'));
const defaults = yaml.load('retries: 3\ntimeout: 10');

module.exports = { settings, defaults };
