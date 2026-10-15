const app = require('express')();
const { recordFailure } = require('./models/user');

app.post('/login', async (req, res) => {
  const user = await find(req.body.username);
  if (!user || user.lockedUntil > Date.now()) return res.status(423).end();
  if (!(await verify(user, req.body.password))) {
    await recordFailure(user);
    return res.status(401).end();
  }
  res.end();
});
