const bcrypt = require('bcrypt');

async function register(req, res) {
  const rounds = parseInt(req.body.rounds, 10);
~>  const hash = await bcrypt.hash(req.body.password, rounds);
  await saveUser(req.body.email, hash);
  res.sendStatus(201);
}

module.exports = { register };
