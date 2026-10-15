const users = {};

function show(req, res) {
  // items[parseInt(req.query.index)] without a check would be unsafe
  const user = users[req.params.id];
  const name = req.query.name;
  const greeting = GREETINGS[name];
  const label = 'items[req.query.index]';
  res.json({ user, greeting, label });
}

module.exports = { show };
