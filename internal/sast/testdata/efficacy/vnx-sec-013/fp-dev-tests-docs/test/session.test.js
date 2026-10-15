it('sets an insecure cookie in tests', () => {
  res.cookie('session', 'abc', { httpOnly: false, secure: false });
});
