export function go(url) {
  window.open(url, '_blank', 'noopener,noreferrer');
  window.open(url, '_self');
  window.open('/help', 'help');
  const w = window.open(url);
  w.opener = null;
  // window.open(url);
  const msg = "call window.open(url) to pop";
}
