const router = require('express').Router();

router.get('/admin', requireAdmin, adminPage);
router.use('/private', ensureLoggedIn(), privateRoutes);
app.use('/admin', authorize('admin'));
