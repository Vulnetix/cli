const express = require('express')
const dgram = require('dgram')

const app = express()

~>app.listen(3000, '0.0.0.0', () => console.log('listening'))

const sock = dgram.createSocket('udp6')
~>sock.bind(5353, "::")
