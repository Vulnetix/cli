const jwt = require('jsonwebtoken');
describe('sign', () => {
  it('signs', () => {
    expect(jwt.sign({ a: 1 }, 'test-secret')).toBeTruthy();
  });
});
