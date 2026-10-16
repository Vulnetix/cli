const express = require('express');
const { parseStringPromise } = require('xml2js');

const router = express.Router();
router.use(express.text({ type: 'application/xml' }));

router.post('/soap/order', async (req, res) => {
  try {
~>    const envelope = await parseStringPromise(req.body, { explicitArray: false });
    const order = envelope['soap:Envelope']['soap:Body'].PlaceOrder;
    res.json({ accepted: order.id });
  } catch (err) {
    res.status(400).send('bad xml');
  }
});

module.exports = router;
