import DOMPurify from 'dompurify';

export function showSpinner(el) {
  el.innerHTML = '<span class="spinner"></span>';
}
export function showMessage(el, html) {
  el.innerHTML = DOMPurify.sanitize(html);
}
export function showName(el, name) {
  el.innerHTML = escapeHtml(name);
}
export function label(el, ok) {
  el.innerHTML = ok ? '<b>yes</b>' : '<i>no</i>';
}
