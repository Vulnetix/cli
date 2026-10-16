const handlers = { start: () => 1, stop: () => 2 };

function route(req, res) {
  const fn = handlers[req.query.name];
  if (!fn) return res.sendStatus(404);
  res.json({ result: fn() });
}

const label = "window[req.query.name] is how not to do it";
module.exports = { route, label };
