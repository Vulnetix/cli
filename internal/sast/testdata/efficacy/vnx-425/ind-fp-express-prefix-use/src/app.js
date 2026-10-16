const express = require('express');
const passport = require('passport');
const admin = require('./controllers/admin');

const app = express();
app.use('/admin', passport.authenticate('jwt', { session: false }), requireRole('admin'));

app.get('/admin/reports', admin.reports);
app.post('/admin/reindex', admin.reindex);

module.exports = app;
