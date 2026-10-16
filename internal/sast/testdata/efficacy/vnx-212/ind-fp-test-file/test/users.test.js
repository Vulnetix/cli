const request = require('supertest');
const User = require('../src/models/User');

test('fixture route returns the user', async () => {
  const app = makeApp((req, res) => {
    const user = User.findOne({ email: 'a@example.com' });
    res.json(user);
  });
  await request(app).get('/').expect(200);
});
