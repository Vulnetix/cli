const express = require('express');
const app = express();
app.get('/ice', (req, res) => res.json({ urls: 'turn:turn.example.org:3478' }));
app.listen(3000);
