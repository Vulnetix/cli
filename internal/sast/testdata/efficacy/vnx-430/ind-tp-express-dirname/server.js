const express = require('express');
const path = require('path');
const routes = require('./routes');

const app = express();
app.use(express.json());
~>app.use('/', express.static(path.join(__dirname)));
app.use('/api', routes);

app.listen(process.env.PORT || 3000);
