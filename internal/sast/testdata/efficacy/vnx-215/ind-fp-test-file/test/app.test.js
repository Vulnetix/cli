const express = require('express');
const errorhandler = require('errorhandler');
const request = require('supertest');

test('renders errors', async () => {
  const app = express();
  app.get('/', () => { throw new Error('boom'); });
  app.use(errorhandler());
  await request(app).get('/').expect(500);
});
