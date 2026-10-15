const EXPECTED = 'https://widgets.example.com';

window.addEventListener(
  'message',
  (evt) => {
    if (evt.origin !== EXPECTED) return;
    render(evt.data);
  },
  false
);
