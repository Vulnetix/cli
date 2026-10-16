const jwt = require('jsonwebtoken');
describe('token', () => {
  it('has claims', () => {
    const t = jwt.sign({ a: 1 }, 'x');
    const c = jwt.decode(t);
    expect(c.a).toBe(1);
  });
});
