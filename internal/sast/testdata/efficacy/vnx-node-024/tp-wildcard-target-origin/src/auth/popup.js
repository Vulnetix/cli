export function finishLogin(token) {
~>  window.opener.postMessage({ type: 'login', token }, '*');
  window.close();
}

export function sendToParent(profile) {
~>  parent.postMessage(JSON.stringify(profile), "*");
}

export function pushToFrame(frame, secret) {
~>  frame.contentWindow.postMessage(
    { secret },
    `*`,
  );
}
