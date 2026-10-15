const fs = require('fs')
const request = require('supertest')
const express = require('express')

const app = express()
app.get('/fixture', (req, res) => {
  res.send(fs.readFileSync(__dirname + '/fixture.json'))
})

test('serves the fixture', async () => {
  await request(app).get('/fixture').expect(200)
})
