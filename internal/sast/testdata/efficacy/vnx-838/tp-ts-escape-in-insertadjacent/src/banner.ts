export function banner(el: HTMLElement, msg: string): void {
~>  el.insertAdjacentHTML('beforeend', `<div class="note">${encodeURIComponent(msg)}</div>`);
~>  $('#status').html('<span>' + encodeURIComponent(msg) + '</span>');
}
