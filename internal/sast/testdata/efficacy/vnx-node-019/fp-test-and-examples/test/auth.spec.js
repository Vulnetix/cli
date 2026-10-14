const jwt = require('jsonwebtoken');

describe('auth', () => {
  it('rejects a token signed with another key', () => {
    const token = jwt.sign({ sub: 'u1' }, 'not-the-server-key');
    expect(() => verify(token)).toThrow();
  });
});
