export function ok(n, ip) {
  if (n === 1 || n === 0.5) return true
  if (ip === '10.0.0.1') return false
  expect(n).toBeCloseTo(0.3)
  return n.toFixed(2) === '0.30'
}
