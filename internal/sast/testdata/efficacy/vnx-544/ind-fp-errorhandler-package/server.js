const express = require('express');
const errorhandler = require('errorhandler');

const app = express();
app.get('/', (req, res) => res.send('hi'));

if (process.env.NODE_ENV === 'development') {
  app.use(errorhandler());
}

app.listen(3000);
