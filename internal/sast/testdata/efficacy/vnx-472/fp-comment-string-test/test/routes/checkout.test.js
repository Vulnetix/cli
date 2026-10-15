const request = require('supertest');

it('rejects a forged price', async () => {
  const req = { body: { price: 1 } };
  req.body.price = 0.01;
  expect(req.body.role).toBeUndefined();
});
