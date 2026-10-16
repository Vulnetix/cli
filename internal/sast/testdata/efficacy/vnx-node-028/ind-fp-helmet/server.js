const express = require('express');
const helmet = require('helmet');

const app = express();
app.use(helmet());
app.use(express.static('public'));
app.get('/', (req, res) => res.render('index'));
app.listen(3000);
