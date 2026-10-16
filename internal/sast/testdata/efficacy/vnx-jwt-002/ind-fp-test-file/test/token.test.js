const jwt = require('jsonwebtoken');

describe('fixtures', () => {
  it('makes a token', () => {
    const t = jwt.sign({ id: 1 }, 'k');
    expect(t).toBeTruthy();
  });
});
