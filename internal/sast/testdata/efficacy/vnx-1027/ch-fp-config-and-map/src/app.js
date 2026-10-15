const config = require('./config');
const handlers = {
  pdf: require('./handlers/pdf'),
  png: require('./handlers/png'),
};
const extra = require(config.pluginPath);

module.exports = function handle(req, res) {
  const handler = handlers[req.params.kind];
  if (!handler) return res.sendStatus(404);
  return handler(req, res, extra);
};
