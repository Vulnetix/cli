export function label(name: string): string {
~>  const safe = name.replace(`<`, `&lt;`);
  return `<span>${safe}</span>`;
}
