import boto3
from datetime import timedelta

iam = boto3.client("iam")
iam.update_account_password_policy(
    MinimumPasswordLength=14,
~>    MaxPasswordAge=365,
)

~>PASSWORD_MAX_AGE = timedelta(days=365)
