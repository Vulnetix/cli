const NodeCache = require("node-cache");
const myCache = new NodeCache();

async function login(req, res, redis) {
  const { username, password } = req.body;
~>  myCache.set(`pw:${username}`, password, 3600);
~>  await redis.set("last-login:" + username, req.body.password);
  res.send("ok");
}
