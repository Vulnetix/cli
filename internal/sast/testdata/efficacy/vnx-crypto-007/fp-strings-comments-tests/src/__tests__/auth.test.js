const crypto = require('crypto');

test('legacy digest', () => {
  const password = 'secret';
  expect(crypto.createHash('md5').update(password).digest('hex')).toHaveLength(32);
});
