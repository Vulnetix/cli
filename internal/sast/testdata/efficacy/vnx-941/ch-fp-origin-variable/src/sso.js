const TARGET_ORIGIN = 'https://accounts.example.com';

export function sendToken(frame, authToken) {
  frame.contentWindow.postMessage({ token: authToken }, TARGET_ORIGIN);
  window.parent.postMessage({ ready: true }, window.location.origin);
  const help = "call postMessage(msg, '*') only for public data";
}
