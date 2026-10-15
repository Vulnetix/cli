const express = require('express')
const multer = require('multer')

const app = express()
app.use(express.json({ limit: '100kb' }))
app.use(express.urlencoded({ extended: false, limit: '1mb', parameterLimit: 1000 }))
app.use(express.raw({ limit: 10485760 }))

const upload = multer({ dest: 'uploads/', limits: { fileSize: 2 * 1024 * 1024, files: 1 } })
const memory = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 200000 }
})

const { Server } = require('socket.io')
const io = new Server(app, { maxHttpBufferSize: 1e6 })
