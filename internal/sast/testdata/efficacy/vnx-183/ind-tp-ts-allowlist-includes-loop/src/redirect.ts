const redirectAllowlist = new Set([
  'https://github.com/acme/app',
  'https://docs.acme.io',
]);

export function isRedirectAllowed(url: string): boolean {
  let allowed = false;
  for (const allowedUrl of redirectAllowlist) {
~>    allowed = allowed || url.includes(allowedUrl);
  }
  return allowed;
}
