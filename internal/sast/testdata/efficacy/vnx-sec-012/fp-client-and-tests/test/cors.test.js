it('sets cors header', async () => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  expect(res.headers['access-control-allow-origin']).toBe('*');
});
