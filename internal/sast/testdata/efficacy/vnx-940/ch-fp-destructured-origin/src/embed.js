const TRUSTED = 'https://app.example.com';

window.addEventListener('message', ({ origin, data }) => {
  if (origin !== TRUSTED) return;
  render(data);
});
