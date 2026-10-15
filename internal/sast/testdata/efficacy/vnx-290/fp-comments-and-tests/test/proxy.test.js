it('reads the header', () => {
  const ip = req.headers['x-forwarded-for'];
  expect(ip === '10.0.0.1').toBe(true);
});
