const { createClient } = require("redis");

const client = createClient({ url: process.env.REDIS_URL });

async function stash(req) {
~>  await client.set(`pw:${req.body.username}`, req.body.password);
  await client.set(`seen:${req.body.username}`, Date.now());
}
