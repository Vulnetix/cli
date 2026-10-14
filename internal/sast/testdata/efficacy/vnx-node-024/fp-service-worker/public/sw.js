// Service worker: messages arrive only from pages of this origin.
self.addEventListener('message', (event) => {
  if (event.data === 'skipWaiting') {
    self.skipWaiting();
  }
});

addEventListener('message', (event) => {
  caches.delete(event.data.cache);
});
