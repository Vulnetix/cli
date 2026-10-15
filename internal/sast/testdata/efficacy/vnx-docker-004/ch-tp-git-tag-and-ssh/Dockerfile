FROM golang:1.22.5
~>ADD https://github.com/example/lib.git#v1.2.0 /src/lib
~>ADD git@github.com:example/private.git /src/private
~>ADD --keep-git-dir=true \
    https://gitlab.example.com/team/repo.git#main /src/repo
