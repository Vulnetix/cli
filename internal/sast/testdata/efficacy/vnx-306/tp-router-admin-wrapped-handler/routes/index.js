const router = require('express').Router();
const utils = require('../utils');

~>router.get('/rest/admin/configuration', utils.asyncHandler(readConfiguration()));

module.exports = router;
