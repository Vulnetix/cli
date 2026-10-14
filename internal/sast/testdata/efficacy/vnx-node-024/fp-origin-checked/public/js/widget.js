const TRUSTED = 'https://app.example.com';

window.addEventListener('message', function (event) {
  if (event.origin !== TRUSTED) {
    return;
  }
  document.getElementById('status').textContent = event.data.status;
});

window.addEventListener('message', (e) => {
  if (!ALLOWED_ORIGINS.includes(e.origin)) return;
  render(e.data);
});

window.addEventListener('message', (e) => {
  if (e.source !== document.getElementById('child').contentWindow) return;
  render(e.data);
});

function onMessage(event) {
  if (event.origin !== TRUSTED) return;
  render(event.data);
}
window.addEventListener('message', onMessage);

parent.postMessage({ ready: true }, TRUSTED);
