const express = require('express');
const app = express();
const PORT = 4000;
~>app.listen(PORT, '0.0.0.0', () => {
  console.log('listening');
});
