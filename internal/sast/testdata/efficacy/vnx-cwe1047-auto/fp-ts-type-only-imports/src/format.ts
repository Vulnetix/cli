export function formatId(prefix: string): string {
  return `${prefix}-${Date.now()}`;
}
