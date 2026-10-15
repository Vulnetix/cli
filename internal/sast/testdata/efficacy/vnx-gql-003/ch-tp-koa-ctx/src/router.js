const Router = require('@koa/router');
const { GraphQLClient } = require('graphql-request');

const client = new GraphQLClient(process.env.GRAPHQL_URL);
const router = new Router();

router.get('/profile/:handle', async (ctx) => {
  const handle = ctx.params.handle;
~>  const data = await client.request(`{ profile(handle: "${handle}") { bio avatar } }`);
  ctx.body = data;
});

module.exports = router;
