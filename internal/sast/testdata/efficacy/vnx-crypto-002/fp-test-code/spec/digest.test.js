const crypto = require('crypto')

test('legacy digests still parse', () => {
  const d = crypto.createHash('sha1').update('x').digest('hex')
  expect(parse(d)).toBeTruthy()
})
