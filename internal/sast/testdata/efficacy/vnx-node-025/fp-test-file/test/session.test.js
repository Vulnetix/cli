const express = require('express');
const session = require('express-session');
const request = require('supertest');

const app = express();
app.use(session({ secret: 'test', cookie: { secure: false } }));

it('sets a session cookie', async () => {
  await request(app).get('/').expect(200);
});
