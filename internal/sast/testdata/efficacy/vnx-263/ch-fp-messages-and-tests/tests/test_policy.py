def test_rejects_long_age(validator):
    assert not validator.ok({"MaxPasswordAge": 90})
    assert validator.limit_days == 180
