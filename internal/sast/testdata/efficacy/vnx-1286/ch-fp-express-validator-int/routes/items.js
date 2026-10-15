const { query, validationResult } = require('express-validator');
const router = require('express').Router();

router.get('/items', query('limit').isInt({ min: 1, max: 100 }), (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  const limit = parseInt(req.query.limit, 10);
  res.json({ limit });
});

module.exports = router;
