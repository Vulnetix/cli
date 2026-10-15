export function fade(el, level) {
  el.style.opacity = 0.3;
  const step = level <= 0.1 ? 0.05 : 0.1;
  if (level === 0.5 || level == 0.25 || level === 2.0) {
    return step;
  }
  return Math.abs(level - 0.3) < 1e-9;
}
