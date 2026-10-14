const { Client, Environment } = require('square');
const client = new Client({
~>  accessToken: '@@sample:EAAA[A-Z]{3}[a-z]{3}[0-9]{3}[A-Za-z0-9_-]{51}@@',
  environment: Environment.Production,
});
