function onMessage(e) {
  if (e.data.type === 'navigate') {
    location.href = e.data.url;
  }
}
~>window.addEventListener('message', onMessage);
