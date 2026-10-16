test('embed cookie', () => {
  res.cookie('embed', 'x', { sameSite: 'none', secure: true });
});
