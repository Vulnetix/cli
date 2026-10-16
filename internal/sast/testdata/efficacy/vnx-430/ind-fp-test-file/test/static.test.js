const express = require('express');
const request = require('supertest');

describe('static fixtures', () => {
  it('serves the fixture directory', async () => {
    const app = express();
    app.use(express.static(__dirname));
    await request(app).get('/fixture.txt').expect(200);
  });
});
