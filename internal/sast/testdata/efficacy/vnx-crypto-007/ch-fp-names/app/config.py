import hashlib

PASSWORD_MIN_LENGTH = 12
password_policy_sha = hashlib.sha256(open("policy.txt", "rb").read()).hexdigest()
