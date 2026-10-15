function check(decoded) {
  if (decoded.header.alg === 'none') {
    throw new Error('alg none rejected');
  }
  const forbidden = ['none'];
  if (forbidden.includes(decoded.header.alg)) throw new Error('bad alg');
}
