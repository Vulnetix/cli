require "aws-sdk-s3"

Aws.config.update(
  region: "us-east-1",
~>  credentials: Aws::Credentials.new(ENV["AWS_ACCESS_KEY_ID"], "@@sample:[A-Za-z0-9/+]{40}@@")
)
