const cors = require('cors');
const { Server } = require('socket.io');

const corsOptions = { origin: '*' };
app.use(cors(corsOptions));

const io = new Server(server, {
  cors: { origin: 'https://app.example.com' },
});
