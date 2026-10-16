#!/bin/sh
export AWS_DEFAULT_REGION=us-east-1
~>export AWS_SECRET_ACCESS_KEY=@@sample:[A-Za-z0-9/+]{40}@@
aws s3 sync build s3://acme-site
