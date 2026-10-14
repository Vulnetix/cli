export function replace(node, html) {
~>  node.outerHTML = html;
}

export function toast(container, message) {
~>  container.insertAdjacentHTML('beforeend', `<div class="toast">${message}</div>`);
}

export function legacy(ref) {
~>  document.write("<a href='" + ref + "'>back</a>");
}
