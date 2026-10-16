const express = require('express');
const request = require('supertest');

describe('GET /ping', () => {
  it('responds', async () => {
    const app = express();
    app.get('/ping', (req, res) => res.send('pong'));
    await request(app).get('/ping').expect(200);
    app.listen(0);
  });
});
