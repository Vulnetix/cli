export function render(el: HTMLElement, html: string): void {
~>  // TODO(alice): sanitize this before it reaches innerHTML
  el.innerHTML = html;
}
