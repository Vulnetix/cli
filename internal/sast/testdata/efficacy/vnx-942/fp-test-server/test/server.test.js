const cors = require('cors');
const express = require('express');

describe('fixture server', () => {
  it('serves', () => {
    const app = express();
    app.use(cors());
    app.get('/', (req, res) => {
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.send('ok');
    });
  });
});
