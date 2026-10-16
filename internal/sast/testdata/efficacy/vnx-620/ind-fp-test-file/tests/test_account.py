def test_change_password(client, user):
    from flask import request
    def change_password():
        new_password = request.form["new_password"]
        user.set_password(new_password)
    change_password()
    assert user.check_password("x")
