const out = document.getElementById('out');

~>window.addEventListener(
  'message',
  (evt) => {
    out.innerHTML = evt.data.html;
  },
  false
);
