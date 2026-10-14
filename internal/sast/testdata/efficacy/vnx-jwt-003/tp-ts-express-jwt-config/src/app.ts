import express from 'express'
import { expressjwt } from 'express-jwt'

const app = express()
~>app.use(expressjwt({ secret: 'shared-hmac-key', algorithms: ['HS256'] }))

export const config = {
~>  jwtSecret: 'another-hmac-key',
  port: 3000,
}
