export function priceToNumber(label: string): number {
  return Number(label.replaceAll('$', '').replaceAll(',', ''));
}

export function dropEllipsis(s: string): string {
  return s.replace(/\.\.\./g, '');
}

export function escapeHtml(s: string): string {
  return s.replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

export function parts(s: string): string[] {
  return s.split('|').join(' ').split(' ');
}
