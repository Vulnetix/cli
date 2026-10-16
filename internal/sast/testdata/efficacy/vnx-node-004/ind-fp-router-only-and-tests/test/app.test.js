const express = require('express');
const request = require('supertest');

const app = express();
app.get('/ping', (req, res) => res.send('pong'));

test('ping', async () => {
  await request(app).get('/ping').expect(200);
});
