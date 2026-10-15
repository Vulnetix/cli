self.addEventListener('message', (e) => {
  const digest = hash(e.data);
  self.postMessage(digest);
});

const w = new Worker('/w.js');
w.postMessage({ cmd: 'start' });
port.postMessage(result);
