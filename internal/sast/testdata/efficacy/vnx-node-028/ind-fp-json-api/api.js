const express = require('express');

const app = express();
app.use(express.json());
app.get('/api/users', (req, res) => {
  res.json([{ id: 1, name: 'ada' }]);
});
app.post('/api/users', (req, res) => res.status(201).json(req.body));
app.listen(4000);
