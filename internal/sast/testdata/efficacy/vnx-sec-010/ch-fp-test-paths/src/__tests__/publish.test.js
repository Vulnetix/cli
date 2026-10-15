const { maskToken } = require('../publish');

test('masks npm tokens', () => {
  const token = 'npm_' + '@@sample:a[1]B2[c]3D[4]e5[F]6g[7]H8[i]9J[0]k1[L]2m[3]N4[o]5P[6]q7[R]8@@';
  expect(maskToken(token)).toBe('npm_****');
});
