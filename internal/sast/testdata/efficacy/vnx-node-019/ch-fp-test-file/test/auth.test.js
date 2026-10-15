const jwt = require('jsonwebtoken');
const { verifyToken } = require('../src/auth');

describe('verifyToken', () => {
  it('accepts a token signed with the configured key', () => {
    const token = jwt.sign({ sub: '42' }, 'test-secret');
    expect(verifyToken(token, 'test-secret').sub).toBe('42');
  });
});
