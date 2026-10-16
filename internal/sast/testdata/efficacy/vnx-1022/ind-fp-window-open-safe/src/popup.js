export function a(url) {
  window.open(url, '_blank', 'noopener,noreferrer');
}
export function b(url) {
  const w = window.open(url, '_blank');
  w.opener = null;
}
export function c(url) {
  window.open(url, '_self');
}
export function d() {
  window.open('https://example.com/help', '_blank');
}
// window.open(userUrl, '_blank');
