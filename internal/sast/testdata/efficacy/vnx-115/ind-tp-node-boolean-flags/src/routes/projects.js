const express = require('express');
const Project = require('../models/project');

const router = express.Router();

router.get('/projects', async (req, res) => {
~>  const includeArchived = Boolean(req.query.archived);
~>  const debug = !!req.headers['x-debug'];
  const projects = await Project.list({ includeArchived });
  if (debug) {
    res.set('X-Query-Count', String(projects.length));
  }
  res.json(projects);
});

router.get('/projects/:id/beta', (req, res) => {
  const optIn = req.cookies.beta_opt_in;
~>  if (Boolean(optIn)) {
    return res.redirect(`/beta/projects/${req.params.id}`);
  }
  res.redirect(`/projects/${req.params.id}`);
});

module.exports = router;
