it('loads', () => {
  const req = { query: { name: 'csv' } };
  const m = require(req.query.name);
  expect(m).toBeDefined();
});
