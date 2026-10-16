const express = require('express');
const serveIndex = require('serve-index');
const request = require('supertest');

test('lists fixtures', async () => {
  const app = express();
  app.use('/fx', serveIndex(__dirname + '/fixtures'));
  await request(app).get('/fx').expect(200);
});
