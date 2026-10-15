it('rejects an expired session', () => {
  const sessionId = Date.now().toString(36);
  expect(lookup(sessionId)).toBeNull();
});
