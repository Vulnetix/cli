const redis = require("./redis");

async function login(req, res) {
~>  await redis.set(`login:${req.body.email}`, req.body.password, "EX", 600);
  res.sendStatus(202);
}
