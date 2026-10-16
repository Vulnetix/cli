const express = require('express');
const { checkJob } = require('../lib/jobs');

const router = express.Router();

router.get('/jobs/:id/wait', async (req, res) => {
  let attempts = parseInt(req.query.attempts, 10);
  let done = false;
~>  while (attempts > 0 && !done) {
    done = await checkJob(req.params.id);
    attempts -= 1;
  }
  res.json({ done });
});

module.exports = router;
