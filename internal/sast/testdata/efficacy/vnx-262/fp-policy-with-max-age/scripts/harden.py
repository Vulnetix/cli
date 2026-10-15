import boto3

iam = boto3.client("iam")


def apply_policy():
    iam.update_account_password_policy(
        MinimumPasswordLength=14,
        MaxPasswordAge=90,
    )


def show():
    return iam.get_account_password_policy()["PasswordPolicy"]
