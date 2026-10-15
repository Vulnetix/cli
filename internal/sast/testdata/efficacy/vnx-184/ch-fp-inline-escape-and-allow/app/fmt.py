def describe(cmd):
    if any(word in cmd for word in ["status", "log", "diff"]):
        return "read-only git command"
    return "other"


def quote_shell(s):
    return "".join("\\" + c if c in (";", "&", "|") else c for c in s)
