export function safeName(name: string): string {
~>  const stripped = name.replaceAll('../', '');
  return stripped;
}

export function stripTags(html: string): string {
~>  return html.replaceAll("<iframe", "");
}
