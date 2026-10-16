export function esc(s: string): string {
~>  return s.replace(/</, '&lt;');
}
