const express = require('express');
const { requireAuth } = require('./middleware');

const router = express.Router();

// Authentication is added by the router middleware below.
// CSRF protection is enabled globally in app.js.
router.use(requireAuth);

// TODO: paginate this list
router.get('/items', async (req, res) => {
  res.json(await req.db.items.list());
});

module.exports = router;
