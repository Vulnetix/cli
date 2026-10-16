const worker = new Worker('w.js');
worker.addEventListener('message', (e) => console.log(e.data));
const ws = new WebSocket('wss://x.example.com');
ws.addEventListener('message', (e) => console.log(e.data));
const ch = new MessageChannel();
ch.port1.addEventListener('message', (e) => console.log(e.data));
