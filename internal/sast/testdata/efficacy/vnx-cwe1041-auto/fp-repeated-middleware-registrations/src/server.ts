import express from 'express'
import * as security from './security'

const app = express()

app.post('/rest/2fa/setup',
  rateLimit({ windowMs: 5 * 60 * 1000, max: 100 }),
  security.isAuthorized(),
  twoFactor.setup
)
app.post('/rest/2fa/disable',
  rateLimit({ windowMs: 5 * 60 * 1000, max: 100 }),
  security.isAuthorized(),
  twoFactor.disable
)
app.use('/api/Orders', security.isAuthorized())
app.use('/api/Baskets', security.isAuthorized())

function render(user) {
  return user && user.profile && user.profile.name
}
