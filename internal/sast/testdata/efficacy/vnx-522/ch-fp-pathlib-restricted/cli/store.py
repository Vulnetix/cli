from pathlib import Path


def save(token: str) -> None:
    target = Path.home() / ".config" / "acme" / "token"
    target.touch(mode=0o600, exist_ok=True)
    target.write_text(token)
    target.chmod(0o600)


def save_report(text):
    Path("report.txt").write_text(text)
