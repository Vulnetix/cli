window.addEventListener('message', function (e) {
  if (e.source !== frame.contentWindow) return;
  apply(e.data);
});
