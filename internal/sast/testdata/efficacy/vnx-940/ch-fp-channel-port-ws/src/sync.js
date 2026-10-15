const channel = new BroadcastChannel('cart');
channel.addEventListener('message', (e) => updateCart(e.data));

const worker = new Worker('/js/hash.js');
worker.addEventListener('message', (e) => showHash(e.data));

const { port1 } = new MessageChannel();
port1.onmessage = (e) => console.log(e.data);

const ws = new WebSocket('wss://feed.example.com');
ws.addEventListener('message', (e) => append(e.data));
