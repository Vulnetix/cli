import { S3Client } from "@aws-sdk/client-s3";

export const s3 = new S3Client({
  credentials: {
    accessKeyId: process.env.AWS_KEY_ID,
~>    secretAccessKey : '@@sample:[A-Za-z0-9/+]{40}@@',
  },
});
