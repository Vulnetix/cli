const express = require('express');
const router = express.Router();

router.get('/items', (req, res) => {
~>  const limit = parseInt(req.get('X-Page-Size'));
~>  const offset = parseInt(req.header('X-Offset'));
  res.json({ limit, offset });
});

async function listHandler(request, reply) {
~>  const page = Number.parseInt(request.query.page);
  return reply.send({ page });
}

module.exports = { router, listHandler };
