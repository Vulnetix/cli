import DOMPurify from 'dompurify';

export function render(el: HTMLElement, html: string, text: string): void {
  el.innerHTML = DOMPurify.sanitize(html);
  el.textContent = text;
  el.innerText = text;
}
