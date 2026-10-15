const worker = new Worker('/static/compute.js');
worker.addEventListener('message', (e) => {
  document.getElementById('result').textContent = e.data;
});

const ws = new WebSocket('wss://feed.example.com');
ws.addEventListener('message', function (e) {
  console.log(e.data);
});

const channel = new BroadcastChannel('tabs');
channel.onmessage = (e) => console.log(e.data);

process.on('message', (m) => console.log(m));
