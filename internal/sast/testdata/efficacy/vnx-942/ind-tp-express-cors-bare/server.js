const express = require('express');
const cors = require('cors');
const app = express();

~>app.use(cors());
app.get('/api/me', (req, res) => res.json(req.user));
