const logger = require("./logger");

async function issueKey(user) {
  const apiKey = await keys.create(user.id);
~>  logger.info(`Generated api key ${apiKey} for ${user.email}`);
~>  console.debug("login payload", { username: user.name, password: @@sample:r[e]q[.][b]od[y][.]p[a]ss[w]or[d]@@ });
  return apiKey;
}
