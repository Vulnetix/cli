export function notifyParent(token) {
~>  window.parent.postMessage({ token }, '*');
}
