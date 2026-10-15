def authorize(principal):
~>    if type(principal).__name__ == "AdminUser":
        return True
~>    if principal.__class__.__name__ in ("ServiceAccount", "Robot"):
        return True
~>    return "SuperUser" == type(principal).__name__
