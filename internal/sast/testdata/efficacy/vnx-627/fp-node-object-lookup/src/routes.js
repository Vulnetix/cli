const handlers = { a: () => 1 };

function route(req, res) {
  const fn = handlers[req.query.name];
  window.config = req.body;
  res.send(global.process.version);
  // global[req.query.name] would be unsafe
}
module.exports = route;
