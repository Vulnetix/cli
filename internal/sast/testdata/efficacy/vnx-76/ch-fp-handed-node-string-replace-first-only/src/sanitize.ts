export function stripScheme(url: string): string {
  return url.replace("javascript:", "");
}

export function stripTags(html: string): string {
  return html.replace(/<script>/gi, "").replace(/<\/script>/gi, "");
}
