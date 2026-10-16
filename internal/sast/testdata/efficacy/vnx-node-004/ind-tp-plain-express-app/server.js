const express = require('express');
const bodyParser = require('body-parser');

~>const app = express();
app.use(bodyParser.json());

app.get('/notes', (req, res) => res.json([]));

app.listen(process.env.PORT || 3000);
