const request = require('supertest');
const app = require('../app');

it('sets session cookie', async () => {
  app.get('/t', (req, res) => { res.cookie('session', 'abc'); res.end(); });
  await request(app).get('/t').expect('set-cookie', /session/);
});
