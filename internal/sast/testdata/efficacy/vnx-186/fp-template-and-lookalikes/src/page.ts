// Remove "<script>" blocks with a case-sensitive replace? Never: use DOMPurify.
const note = 'Strings like "<script>" are escaped by the template engine';

export function inject(template: string, subs: string): string {
  return template.replace('<script id="subtitle"></script>', '<script id="subtitle" type="text/vtt">' + subs + '</script>');
}

export function slug(s: string): string {
  return s.replace(/[^a-z0-9]+/g, '-');
}
