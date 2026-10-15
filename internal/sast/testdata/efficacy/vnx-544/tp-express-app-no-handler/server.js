const express = require('express');
const db = require('./db');

~>const app = express();
app.use(express.json());

app.get('/users/:id', async (req, res) => {
  const user = await db.findUser(req.params.id);
  res.json(user);
});

app.listen(3000);
