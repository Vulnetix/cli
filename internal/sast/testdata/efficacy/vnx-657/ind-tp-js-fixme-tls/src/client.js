const https = require('https')

const agent = new https.Agent({
~>  rejectUnauthorized: false, // FIXME: SSL verification disabled for staging
})
