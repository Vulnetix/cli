window.addEventListener('message', (event) => {
  if (event.origin !== 'https://app.example.com') return;
  handle(event.data);
});
