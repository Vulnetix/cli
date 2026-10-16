export function send(win, msg) {
  win.postMessage(msg, 'https://app.example.com');
  window.postMessage(msg, window.location.origin);
}
