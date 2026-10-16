const express = require('express');
const repo = require('./repo');

const router = express.Router();

router.get('/items', async (req, res) => {
  const pageParam = req.query.page;
  const sort = req.query.sort === 'asc' ? 'asc' : 'desc';
  const filters = {};

  if (req.query.category) {
    filters.category = String(req.query.category);
  }
  if (req.query.tag) {
    filters.tag = String(req.query.tag);
  }
  if (req.query.owner) {
    filters.owner = String(req.query.owner);
  }

  const pageSize = 50;
  const total = await repo.count(filters);
  const pages = Math.ceil(total / pageSize);
~>  const page = Math.min(parseInt(pageParam), pages);

  const items = await repo.list(filters, { sort, offset: (page - 1) * pageSize, limit: pageSize });
  res.json({ items, page, pages });
});

module.exports = router;
