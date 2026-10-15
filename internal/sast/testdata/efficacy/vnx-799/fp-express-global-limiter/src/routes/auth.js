const router = require('express').Router();
const ctrl = require('../controllers/auth');

router.post('/login', ctrl.login);
router.post('/forgot-password', ctrl.forgot);
module.exports = router;
