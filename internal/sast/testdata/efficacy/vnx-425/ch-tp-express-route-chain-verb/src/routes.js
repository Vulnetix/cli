const express = require('express');
const router = express.Router();
const ctrl = require('./controllers/admin');

~>router.route('/admin/users/:id').delete(ctrl.removeUser);

router.route('/profile').get(ctrl.profile);

module.exports = router;
