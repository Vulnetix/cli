const express = require('express');
const router = express.Router();
const ctrl = require('./controllers/admin');
const { requireAdmin } = require('./middleware/roles');

router.route('/admin/users').all(requireAdmin).get(ctrl.list);
router.route('/admin/users/:id').delete(requireAdmin, ctrl.removeUser);

module.exports = router;
