const frame = document.getElementById('f');
window.addEventListener('message', function (e) {
  if (e.source !== frame.contentWindow) return;
  handle(e.data);
});
