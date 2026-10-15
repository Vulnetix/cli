const TRUSTED = 'https://app.example.com';

window.addEventListener('message', function (event) {
  if (event.origin !== TRUSTED) {
    return;
  }
  render(event.data);
});

function onMsg({ origin, data }) {
  if (origin === TRUSTED) render(data);
}
window.addEventListener('message', onMsg);

window.onmessage = (e) => {
  if (e.source !== document.getElementById('child').contentWindow) return;
  render(e.data);
};

function render(d) {
  document.getElementById('x').textContent = String(d);
}
