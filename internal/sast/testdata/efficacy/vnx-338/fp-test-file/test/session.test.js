describe('session', () => {
  it('rejects an unknown token', async () => {
    const sessionToken = Math.random().toString(36);
    expect(await lookup(sessionToken)).toBeNull();
  });
});
