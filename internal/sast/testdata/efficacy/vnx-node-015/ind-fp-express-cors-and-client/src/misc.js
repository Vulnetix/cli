const cors = require('cors');
app.use(cors({ origin: '*' }));

const sock = new WebSocket('wss://feed.example.com/stream');
sock.onmessage = (e) => console.log(e.data);
