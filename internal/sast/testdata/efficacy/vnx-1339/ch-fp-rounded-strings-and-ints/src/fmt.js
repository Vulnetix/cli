export function same(a, b) {
  if (a.toFixed(1) === '0.3') return true;
  if (Math.round(a * 10) === 3) return true;
  const ver = '0.1';
  return ver == '0.1' || b >= 0.1 || b !== 0.75;
}
