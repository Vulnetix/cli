const express = require('express');
const app = express();
app.post('/login', (req, res) => res.sendStatus(200));
describe('login stub', () => { it('works', () => {}); });
