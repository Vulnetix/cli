const { describeClient } = require('../src/ip');

test('reads forwarded chain', () => {
  const req = { headers: { 'x-forwarded-for': '127.0.0.1, 10.0.0.1' }, socket: {} };
  const ip = req.headers['x-forwarded-for'];
  if (ip === '127.0.0.1') throw new Error('unexpected');
  expect(describeClient(req).via).toBe('proxy');
});
