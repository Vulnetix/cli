const ALLOWED = new Set(['https://app.example.com', 'https://admin.example.com']);

function onMessage(event) {
  if (!ALLOWED.has(event.origin)) {
    return;
  }
  render(event.data);
}

window.addEventListener('message', onMessage);

window.addEventListener('message', (e) => {
  if (e.origin !== window.location.origin) return;
  render(e.data);
});

function render(d) { console.log(d); }
