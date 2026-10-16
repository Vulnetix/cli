export function isTrustedWebhookHost(hostname: string): boolean {
  return /\.trusted-partner\.net$/.test(hostname);
}
