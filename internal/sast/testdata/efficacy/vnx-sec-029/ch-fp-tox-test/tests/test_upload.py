FAKE = "@@sample:p[y]pi[-]Ag[E]Ic[H]lw[a]S5[v]cm[c]@@@@sample:[A-Za-z0-9_-]{120}@@"


def test_masks_token():
    assert "pypi-" in FAKE
