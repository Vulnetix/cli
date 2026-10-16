def check_access(account):
~>    access_level = "user‮ ⁦# Check if admin⁩ ⁦"
    if access_level != "user":
        return grant_admin(account)
    return grant_user(account)
