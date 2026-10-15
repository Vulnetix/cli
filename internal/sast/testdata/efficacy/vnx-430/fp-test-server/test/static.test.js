const express = require('express');
const request = require('supertest');

describe('static', () => {
  it('serves fixtures', async () => {
    const app = express();
    app.use(express.static(__dirname));
    await request(app).get('/static.test.js').expect(200);
  });
});
