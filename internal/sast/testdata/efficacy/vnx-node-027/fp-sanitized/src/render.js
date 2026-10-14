import DOMPurify from 'dompurify';
import { escapeHtml } from './escape';

export function render(el, html, name) {
  el.innerHTML = DOMPurify.sanitize(html);
  el.innerHTML = '<b>' + escapeHtml(name) + '</b>';
  const clean = DOMPurify.sanitize(html, { ALLOWED_TAGS: ['b', 'i'] });
  el.innerHTML = clean;
}
