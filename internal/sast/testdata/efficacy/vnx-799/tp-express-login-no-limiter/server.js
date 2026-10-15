const express = require('express');
const auth = require('./auth');

const app = express();
app.use(express.json());

// Password check runs on every request; nothing caps how often it is tried.
~>app.post('/login', async (req, res) => {
  const user = await auth.check(req.body.username, req.body.password);
  if (!user) return res.status(401).end();
  res.json({ token: auth.issue(user) });
});

const router = express.Router();
~>router.post("/api/auth/reset-password", auth.resetPassword);
router.get('/api/products', (req, res) => res.json([]));
app.use(router);
app.listen(3000);
