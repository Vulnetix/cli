window.addEventListener('message', (event) => {
  if (event.origin !== 'https://app.example.com') return;
  handle(event.data);
});

window.addEventListener('message', ({ origin, data }) => {
  if (!ALLOWED.includes(origin)) return;
  handle(data);
});
