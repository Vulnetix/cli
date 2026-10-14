const yaml = require('js-yaml');

// js-yaml 4 removed the !!js/* types from load(); it is the safe loader.
function importPlaybook(req, res) {
  const playbook = yaml.load(req.body);
  res.json(playbook);
}

module.exports = { importPlaybook };
