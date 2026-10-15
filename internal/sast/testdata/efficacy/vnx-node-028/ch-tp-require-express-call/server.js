~>const app = require('express')();

app.set('view engine', 'ejs');
app.get('/', (req, res) => res.render('index', { user: req.query.user }));
app.listen(3000);
