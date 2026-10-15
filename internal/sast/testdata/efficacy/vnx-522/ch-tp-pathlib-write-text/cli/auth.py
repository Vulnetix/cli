from pathlib import Path


def save(token: str) -> None:
    target = Path.home() / ".config" / "acme" / "token"
    target.parent.mkdir(parents=True, exist_ok=True)
~>    target.write_text(token)


def save_netrc(host, user, password):
~>    Path("~/.netrc").expanduser().write_text(f"machine {host} login {user} password {password}\n")
