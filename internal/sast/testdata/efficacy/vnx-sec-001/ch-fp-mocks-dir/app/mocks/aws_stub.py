FAKE_ACCESS_KEY_ID = "@@sample:AKIA[A-Z2-7]{16}@@"


def stub_session():
    return {"aws_access_key_id": FAKE_ACCESS_KEY_ID}
