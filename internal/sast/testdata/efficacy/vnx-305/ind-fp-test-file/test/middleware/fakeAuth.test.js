const request = require('supertest');
const express = require('express');

function fakeAuth(req, res, next) {
  const token = req.headers.authorization;
  if (token) return next();
  res.sendStatus(401);
}

test('passes through with any header', async () => {
  const app = express();
  app.get('/x', fakeAuth, (req, res) => res.send('ok'));
  await request(app).get('/x').set('Authorization', 'Bearer x').expect(200);
});
