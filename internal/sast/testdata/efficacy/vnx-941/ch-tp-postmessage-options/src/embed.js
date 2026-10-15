export function reply(frame, secret) {
~>  frame.contentWindow.postMessage({ secret }, { targetOrigin: '*' });
}
