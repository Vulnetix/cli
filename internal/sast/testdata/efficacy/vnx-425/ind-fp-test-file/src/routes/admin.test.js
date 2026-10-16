const express = require('express');
const request = require('supertest');

test('admin route', async () => {
  const app = express();
  app.get('/admin/ping', (req, res) => res.send('pong'));
  await request(app).get('/admin/ping').expect(200);
});
