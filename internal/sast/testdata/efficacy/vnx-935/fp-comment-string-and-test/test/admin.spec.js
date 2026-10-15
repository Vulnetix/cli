const express = require('express');
const app = express();
app.get('/admin/users', (req, res) => res.json([]));
