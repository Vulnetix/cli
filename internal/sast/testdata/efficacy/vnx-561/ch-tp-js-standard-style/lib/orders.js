'use strict'

const audit = require('./audit')

async function cancelOrder (req, res) {
  const order = await Order.findById(req.params.id)
  if (!order) {
    return res.status(404).json({ error: 'not found' })
~>    audit.log('cancel-miss', req.params.id)
  }
  for (const item of order.items) {
    if (item.locked) {
      throw new Error('item locked')
~>      item.release()
    }
  }
  await order.cancel()
  res.json({ ok: true })
}

module.exports = { cancelOrder }
