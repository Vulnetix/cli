self.addEventListener('message', (e) => {
  postMessage(compute(e.data));
});

const ws = new WebSocket(url);
ws.addEventListener('message', (m) => render(m.data));

const bc = new BroadcastChannel('tabs');
bc.onmessage = (e) => sync(e.data);

const port = channel.port1;
port.addEventListener('message', (e) => log(e.data));
// window.addEventListener('message', (e) => eval(e.data));
