const request = require('supertest');
const app = require('../app');

// the handler does res.redirect(req.query.url) in the old version
test('redirects', async () => {
  const res = await request(app).get('/go?url=/x');
  const target = res.req.query.url;
  expect(res.status).toBe(302);
});
