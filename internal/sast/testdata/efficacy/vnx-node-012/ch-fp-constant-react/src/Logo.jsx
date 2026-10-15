const LOGO_SVG = '<svg viewBox="0 0 10 10"><circle r="4" /></svg>';

export function Logo() {
  return <span dangerouslySetInnerHTML={{ __html: LOGO_SVG }} />;
}
