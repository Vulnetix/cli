const express = require('express');
const { errorHandler } = require('./middleware/errors');

const app = express();
app.get('/health', (req, res) => res.send('ok'));
app.use(errorHandler);

app.listen(3000);
