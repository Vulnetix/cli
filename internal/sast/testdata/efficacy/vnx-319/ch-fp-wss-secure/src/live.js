export function connect(onTick) {
  const socket = new WebSocket('wss://quotes.acme-corp.com/stream');
  const dev = new WebSocket('ws://localhost:8080/stream');
  socket.onmessage = (e) => onTick(JSON.parse(e.data));
  return [socket, dev];
}
