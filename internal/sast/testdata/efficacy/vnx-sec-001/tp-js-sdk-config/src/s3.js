const { S3Client } = require("@aws-sdk/client-s3");

const s3 = new S3Client({
  region: "us-east-1",
~>  credentials: { accessKeyId: `@@sample:AKIA[A-Z2-7]{16}@@`, secretAccessKey: process.env.AWS_SECRET },
});

module.exports = s3;
