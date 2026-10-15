const MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;' };

export function escapeHtml(s) {
  return s.replace(/[&<>]/g, (c) => MAP[c]);
}

export function isLetter(c) {
  return ['a', 'b', 'c'].includes(c);
}
