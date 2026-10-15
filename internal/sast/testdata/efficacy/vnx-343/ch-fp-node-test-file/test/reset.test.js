let resetCode = 1000;

test('reset codes advance', () => {
  resetCode += Math.floor(Math.random() * 100);
  expect(resetCode).toBeGreaterThan(1000);
});
