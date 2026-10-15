const AWS = require("aws-sdk");

AWS.config.update({
  region: "us-west-2",
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
~>  secretAccessKey: '@@sample:[A-Za-z0-9/+]{40}@@',
});
