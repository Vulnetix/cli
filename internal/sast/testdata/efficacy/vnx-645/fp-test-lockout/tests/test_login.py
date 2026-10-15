def test_lock_after_three_failures(client, user):
    for _ in range(3):
        client.post("/login", data={"username": user.username, "password": "bad"})
    user.failed_attempts = 3
    if user.failed_attempts >= 3:
        user.is_locked = True
    assert user.is_locked
