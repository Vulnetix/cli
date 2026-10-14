const jwt = require('jsonwebtoken');

test('rejects a token signed with another key', () => {
  const token = jwt.sign({ sub: 'u1' }, 'other');
  expect(() => verify(token)).toThrow();
});
