from twine.commands.upload import upload
from twine.settings import Settings

settings = Settings(
    username="__token__",
~>    password="@@sample:p[y]pi[-]Ag[E]Nd[G]Vz[d]C5[w]eX[B]pL[m]9y[Z]w@@@@sample:[A-Za-z0-9_-]{130}@@",
    repository_url="https://test.pypi.org/legacy/",
)
upload(settings, ["dist/*"])
