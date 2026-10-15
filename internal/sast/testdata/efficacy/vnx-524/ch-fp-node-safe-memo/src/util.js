const memoize = require("lodash/memoize");

const loadConfig = memoize((env) => readConfig(env));

async function storeHash(redis, user, hashedPassword) {
  await redis.set(`pw:${user.id}`, hashedPassword);
  await redis.set(`msg:${user.id}`, "password changed");
}
