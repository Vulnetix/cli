const SVG_NS = 'http://www.w3.org/2000/svg';

export function makeCircle(r) {
  const el = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
  el.setAttribute('r', String(r));
  return el;
}
