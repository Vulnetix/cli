const express = require('express');
const request = require('supertest');

const app = express();
app.get('/', (req, res) => res.send('ok'));
app.listen(0);
