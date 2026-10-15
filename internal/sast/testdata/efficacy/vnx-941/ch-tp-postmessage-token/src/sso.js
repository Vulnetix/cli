export function sendToken(frame, authToken) {
~>  frame.contentWindow.postMessage({ type: 'token', token: authToken }, "*");
}

export function notifyParent(payload) {
~>  window.top.postMessage(JSON.stringify(payload), '*');
}
