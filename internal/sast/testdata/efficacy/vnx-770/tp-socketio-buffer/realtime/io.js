const { Server } = require('socket.io')

~>const io = new Server(httpServer, { maxHttpBufferSize: 1e9 })

module.exports = io
