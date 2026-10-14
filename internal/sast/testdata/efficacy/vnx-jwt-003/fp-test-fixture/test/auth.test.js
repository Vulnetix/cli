const jwt = require('jsonwebtoken');

test('rejects tampered tokens', () => {
  const token = jwt.sign({ sub: 'u1' }, 'test-secret-value');
  expect(verify(token)).toBe(false);
});
