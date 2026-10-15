export function go(url) {
  window.open(url, '_self');
}

export function popup(url) {
  const w = window.open(url, 'preview', 'noopener,noreferrer,width=600');
  return w;
}
