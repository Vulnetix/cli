export function connect(onTick) {
~>  const socket = new WebSocket('ws://quotes.acme-corp.com/stream');
  socket.onmessage = (e) => onTick(JSON.parse(e.data));
  return socket;
}
