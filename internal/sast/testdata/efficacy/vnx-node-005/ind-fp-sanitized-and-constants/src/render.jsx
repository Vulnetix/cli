import DOMPurify from 'dompurify';

const SPINNER_SVG = '<svg viewBox="0 0 8 8"></svg>';

export function Rich({ html }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;
}

export function Spinner() {
  return <span dangerouslySetInnerHTML={{ __html: SPINNER_SVG }} />;
}

export function show(el, text, host) {
  el.textContent = text;
  host.insertAdjacentHTML('beforeend', '<hr class="divider">');
  host.insertAdjacentHTML('afterbegin', DOMPurify.sanitize(text));
  document.write('<script src="/static/boot.js"></' + 'script>');
}
