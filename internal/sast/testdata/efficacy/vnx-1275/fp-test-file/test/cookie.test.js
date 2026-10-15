it('allows none', () => {
  res.cookie('session', 't', { sameSite: 'none', secure: true });
});
