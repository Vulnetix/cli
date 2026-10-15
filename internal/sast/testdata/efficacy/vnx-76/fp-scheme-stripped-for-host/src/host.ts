export function hostOf(url: string): string {
  return url.replace('https://', '').replace(/\/.*/, '');
}
