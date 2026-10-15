const app = require('express')();

app.get('/login', (req, res) => res.render('login'));
app.post('/logins/export', exportLogins);
app.post('/api/blog-in-review', review);
