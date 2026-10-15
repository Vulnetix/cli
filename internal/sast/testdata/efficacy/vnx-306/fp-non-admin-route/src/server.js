const app = require('express')();
app.get('/administrators-guide', (req, res) => res.render('guide'));
app.get('/api/badminton/courts', listCourts);
app.get('/users/:id', showUser);
