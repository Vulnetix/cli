const jwt = require('jsonwebtoken');
const { login } = require('../src/login');

test('issues a token for alice', async () => {
  const token = await login('alice', 'pw');
  const claims = jwt.decode(token);
  expect(claims.sub).toBe('alice');
});
