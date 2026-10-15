MIN_PASSWORD_LENGTH = 12


def validate(form, user):
    password = form.get("password")
    if password is None or password == "":
        return "required"
    if form["password"] != form["password_confirmation"]:
        return "mismatch"
    if password != confirm_password:
        return "mismatch"
    if len(password) < MIN_PASSWORD_LENGTH:
        return "short"
    if user.password == None:
        return "no password set"
    if new_password == old_password:
        return "reuse"
    if password_policy == "strict":
        return "strict"
    if user.password_changed == True:
        return "changed"
    if passport_number == expected_number:
        return "ok"
    if password == DEFAULT_PASSWORD:
        return "default"
    return None


class BasicAuth:
    def __eq__(self, other):
        return all([
            self.username == getattr(other, "username", None),
            self.password == getattr(other, "password", None),
        ])

    def same(self, other):
        return self.password == other.password
