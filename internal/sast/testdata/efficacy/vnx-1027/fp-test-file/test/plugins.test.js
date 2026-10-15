it('loads', () => {
  const req = { query: { name: './fixture' } };
  const p = require(req.query.name);
});
