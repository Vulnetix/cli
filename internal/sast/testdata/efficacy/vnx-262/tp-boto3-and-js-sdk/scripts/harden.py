import boto3

iam = boto3.client("iam")


def apply_policy():
~>    iam.update_account_password_policy(
        MinimumPasswordLength=14,
        RequireSymbols=True,
        PasswordReusePrevention=24,
    )
