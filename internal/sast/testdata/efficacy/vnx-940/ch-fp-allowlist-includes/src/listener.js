const ALLOWED = ['https://a.example.com', 'https://b.example.com'];

function handler(e) {
  if (!ALLOWED.includes(e.origin)) {
    return;
  }
  applySettings(e.data);
}

window.addEventListener("message", handler);
