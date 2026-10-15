const { request } = require('graphql-request');

async function hello(req, res) {
  const name = req.query.name;
  const query = "{ viewer { login } }";
  const greeting = "Hello " + name;
  const data = await request(process.env.GQL_URL, query);
  res.json({ greeting, data });
}

module.exports = { hello };
