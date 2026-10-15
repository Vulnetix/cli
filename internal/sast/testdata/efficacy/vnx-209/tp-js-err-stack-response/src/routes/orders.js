const express = require('express');
const router = express.Router();

router.get('/orders/:id', async (req, res) => {
  try {
    res.json(await Orders.get(req.params.id));
  } catch (err) {
~>    res.status(500).send(err.stack);
  }
});

router.post('/orders', async (req, res) => {
  try {
    res.json(await Orders.create(req.body));
  } catch (error) {
~>    res.status(500).json({
      message: error.message,
      stack: error.stack,
    });
  }
});

function errorMiddleware(e, req, res, next) {
  const details = e.stack;
~>  res.end(details);
}

module.exports = { router, errorMiddleware };
