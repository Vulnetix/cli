const CHILD_ORIGIN = 'https://widgets.example.com';
const frame = document.querySelector('iframe');
frame.contentWindow.postMessage({ token: 'x' }, CHILD_ORIGIN);
window.parent.postMessage({ ready: true }, 'https://app.example.com');
window.opener.postMessage(
  { status: 'done' },
  location.origin
);
