const { readFileSync, writeFileSync } = require('fs');
const express = require('express');
const app = express();

app.post('/notes', (req, res) => {
~>  const existing = readFileSync('./notes.json', 'utf8');
  const notes = JSON.parse(existing);
  notes.push(req.body);
~>  writeFileSync('./notes.json', JSON.stringify(notes));
  res.sendStatus(201);
});

app.listen(3000);
