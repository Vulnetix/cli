import DOMPurify from 'dompurify';
import escapeHtml from 'escape-html';

export function show(el, html, name) {
  el.innerHTML = DOMPurify.sanitize(html);
  el.querySelector('.name').innerHTML = '<b>' + escapeHtml(name) + '</b>';
  el.querySelector('.hash').textContent = location.hash.slice(1);
}

export function Comment({ body }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(body) }} />;
}
