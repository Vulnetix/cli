const request = require('supertest');
const session = require('express-session');
const express = require('express');

describe('session', () => {
  it('works over http in tests', async () => {
    const app = express();
    app.use(session({ secret: 's', cookie: { secure: false, httpOnly: false } }));
    await request(app).get('/').expect(404);
  });
});
