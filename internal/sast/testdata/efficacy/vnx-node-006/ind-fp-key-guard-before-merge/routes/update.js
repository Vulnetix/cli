const _ = require('lodash');

function hasBadKey(o) {
  return JSON.stringify(o).includes('__proto__') || JSON.stringify(o).includes('constructor');
}

module.exports = (req, res) => {
  if (hasBadKey(req.body)) {
    return res.status(400).json({ error: 'bad key' });
  }
  const target = {};
  _.merge(target, req.body);
  res.json(target);
};
