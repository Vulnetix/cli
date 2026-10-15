def build_user(name, upn, initial_password):
    return {
        "accountEnabled": True,
        "displayName": name,
        "userPrincipalName": upn,
~>        "passwordPolicies": "DisablePasswordExpiration",
        "passwordProfile": {"password": initial_password, "forceChangePasswordNextSignIn": True},
    }


def make_service_account(conn, dn):
~>    conn.modify(dn, {"userAccountControl": [("MODIFY_REPLACE", [66048])]})
