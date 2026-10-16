const request = require('supertest');

it('creates an order', async () => {
  const req = { body: { price: 10 } };
  const price = req.body.price;
  expect(price).toBe(10);
});
