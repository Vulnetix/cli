const express = require('express');
const request = require('supertest');

const app = express();
app.get('/', (req, res) => res.render('index'));

it('renders', () => request(app).get('/').expect(200));
