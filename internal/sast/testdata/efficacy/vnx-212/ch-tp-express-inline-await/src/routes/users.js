const express = require('express');
const User = require('../models/user');
const router = express.Router();

router.get('/:id', async (req, res) => {
~>  res.json(await User.findById(req.params.id));
});

router.get('/', async (req, res) => {
~>  return res.status(200).send(await User.find({ active: true }));
});

module.exports = router;
