const express = require('express');
const request = require('supertest');

const app = express();
app.use(express.static('fixtures'));

it('serves html', async () => {
  await request(app).get('/index.html').expect(200);
});
