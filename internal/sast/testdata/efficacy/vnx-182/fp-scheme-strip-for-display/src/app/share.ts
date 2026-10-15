export function displayHost(url: string): string {
  return url.replace('https://', '').replace(/\/.*/, '');
}

export function domainKey(domain: string): string {
  return domain.replace("http://", "").toLowerCase();
}
