import express from 'express'
import helmet from 'helmet'

const app = express()
app.use(helmet.noSniff())
app.use(helmet.frameguard())
export default app
