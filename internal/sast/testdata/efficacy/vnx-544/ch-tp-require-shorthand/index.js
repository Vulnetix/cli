~>const app = require('express')();
const bodyParser = require('body-parser');

app.use(bodyParser.json());
app.post('/orders', (req, res, next) => {
  createOrder(req.body).then((o) => res.json(o)).catch(next);
});

app.listen(process.env.PORT || 3000);
