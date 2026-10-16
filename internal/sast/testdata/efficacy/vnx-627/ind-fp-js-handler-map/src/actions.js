const handlers = {
  ping: () => 'pong',
  time: () => new Date().toISOString(),
};

function dispatch(req, res) {
  const fn = handlers[req.query.name];
  if (typeof fn !== 'function') {
    return res.status(404).json({ error: 'unknown action' });
  }
  const config = window.__APP_CONFIG__ || {};
  res.json({ result: fn(), build: config.build, mode: global.process.env.NODE_ENV });
}

module.exports = { dispatch };
