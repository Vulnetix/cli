import boto3

iam = boto3.client("iam")
iam.update_account_password_policy(
    MinimumPasswordLength=14,
~>    MaxPasswordAge=730,
)
