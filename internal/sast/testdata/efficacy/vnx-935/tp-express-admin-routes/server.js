const express = require('express');
const db = require('./db');
const utils = require('./utils');
const { exportUsers } = require('./admin/export');

const app = express();
app.use(express.json());

~>app.get('/admin/users', async (req, res) => {
  res.json(await db.users.findAll());
});

~>app.post("/api/admin/users/:id/promote", function (req, res) {
  db.users.update({ role: 'admin' }, { where: { id: req.params.id } });
  res.sendStatus(204);
});

~>app.get('/rest/admin/export', utils.asyncHandler(exportUsers()));

app.get('/products', async (req, res) => {
  res.json(await db.products.findAll());
});

app.listen(3000);
