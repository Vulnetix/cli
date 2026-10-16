const stripe = require('stripe')

const config = {
  mode: 'test',
  sandbox: false,
  merchantId: process.env.MERCHANT_ID,
}

module.exports = { config, client: stripe(process.env.STRIPE_KEY) }
