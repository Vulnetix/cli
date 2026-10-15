const express = require('express');
const passport = require('passport');
const app = express();

app.use('/admin', passport.authenticate('jwt', { session: false }));
app.get('/admin/users', listUsers);
