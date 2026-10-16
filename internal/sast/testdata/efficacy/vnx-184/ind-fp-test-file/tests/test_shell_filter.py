import pytest

from app.shell import run_ping

BAD_INPUTS = ["8.8.8.8; id", "8.8.8.8 && id", "8.8.8.8 | id", "$(id)"]
SHELL_BLACKLIST = [";", "&&", "|"]


@pytest.mark.parametrize("value", BAD_INPUTS)
def test_rejects_shell_metacharacters(value):
    for tok in SHELL_BLACKLIST:
        if tok in value:
            break
    with pytest.raises(ValueError):
        run_ping(value)
