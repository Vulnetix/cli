const worker = new Worker('/js/hash-worker.js');
worker.addEventListener('message', (e) => {
  console.log('hash', e.data);
});

const channel = new BroadcastChannel('sync');
channel.onmessage = (e) => console.log(e.data);

const ws = new WebSocket('wss://example.com/live');
ws.addEventListener('message', (e) => console.log(e.data));

worker.postMessage({ cmd: 'start' });
