const express = require('express');

const app = express();
app.use(express.json());
app.get('/api/items', (req, res) => res.json([{ id: 1 }]));
app.post('/api/items', (req, res) => res.status(201).json(req.body));
app.listen(4000);
