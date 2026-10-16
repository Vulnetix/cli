def non_expiring(users):
    flagged = []
    for u in users:
        if u.get("passwordPolicies") == "DisablePasswordExpiration":
            flagged.append(u["userPrincipalName"])
    return flagged


def ad_never_expires(uac: int) -> bool:
    UF_DONT_EXPIRE_PASSWD = 0x10000
    return bool(uac & UF_DONT_EXPIRE_PASSWD)
