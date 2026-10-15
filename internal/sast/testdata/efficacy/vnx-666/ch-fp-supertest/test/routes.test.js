const request = require('supertest');

it('creates', async () => {
  const res = await request(app).post('/items').send({ name: 'a' });
  expect(res.status).toBe(201);
  res.body.should.have.property('id');
});
