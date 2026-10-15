export function requireKey(apiKey: string): void {
  if (!apiKey.startsWith('sk_')) {
~>    throw new TypeError(`malformed key ${apiKey}`);
  }
}
