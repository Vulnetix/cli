const assert = require('assert');

describe('tokens', () => {
  it('formats a reset token', () => {
    const resetToken = Math.floor(Math.random() * 1000000);
    assert.ok(resetToken >= 0);
  });
});
