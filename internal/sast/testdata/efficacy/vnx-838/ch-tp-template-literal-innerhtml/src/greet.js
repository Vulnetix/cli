export function greet(el, name) {
~>  el.innerHTML = `<p class="hello">Hello ${encodeURI(name)}</p>`;
}
