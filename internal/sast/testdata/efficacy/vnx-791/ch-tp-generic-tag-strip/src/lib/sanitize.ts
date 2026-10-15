export const stripTags = (input = '') =>
~>  input.replace(/<(?:\w+)\W+?[\w]/gi, '')

export function plain(html: string): string {
~>  return html.replace(/<\/?\w+[^>]*>/g, '');
}

export function textOnly(html: string): string {
  // [^>]* swallows a nested '<', so this one is not reported
  return html.replace(/<[^>]*>/g, '');
}
