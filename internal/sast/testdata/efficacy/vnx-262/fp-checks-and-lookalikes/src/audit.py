UF_DONT_EXPIRE_PASSWD = 0x10000


def never_expires(entry):
    return bool(int(entry["userAccountControl"]) & UF_DONT_EXPIRE_PASSWD)


def normal_account(conn, dn):
    conn.modify(dn, {"userAccountControl": [("MODIFY_REPLACE", [512])]})


def report(user):
    if user.get("passwordPolicies") == "DisablePasswordExpiration":
        print("account never expires:", user["id"])
    return {"password_expires": True, "session_expires": False}
