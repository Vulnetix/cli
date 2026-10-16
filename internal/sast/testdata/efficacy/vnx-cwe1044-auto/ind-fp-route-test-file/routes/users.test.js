const request = require('supertest');
const knex = require('../knex');

describe('users', () => {
  beforeEach(async () => {
    await knex.raw('DELETE FROM users');
  });
  it('lists', async () => {
    const res = await request(app).get('/users');
    expect(res.status).toBe(200);
  });
});
