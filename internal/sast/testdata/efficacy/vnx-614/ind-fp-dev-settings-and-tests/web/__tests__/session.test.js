const request = require('supertest');
const express = require('express');

test('sets a session cookie', async () => {
  const app = express();
  app.get('/', (req, res) => {
    res.cookie('session', 'abc', { secure: false });
    res.cookie('token', 'abc');
    res.send('ok');
  });
  const res = await request(app).get('/');
  expect(res.headers['set-cookie']).toBeDefined();
});
