const frame = document.getElementById('preview');

~>window.addEventListener('message', function (event) {
  const cmd = event.data;
  if (cmd.type === 'navigate') {
    window.location.href = cmd.url;
  }
  if (cmd.type === 'render') {
    frame.innerHTML = cmd.html;
  }
});
