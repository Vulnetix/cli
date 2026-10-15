const express = require('express')

const app = express()
const host = process.env.HOST || '127.0.0.1'

app.listen(3000)
app.listen(3000, 'localhost')
app.listen(3000, host)
app.listen({ port: 3000, host: '127.0.0.1' })
