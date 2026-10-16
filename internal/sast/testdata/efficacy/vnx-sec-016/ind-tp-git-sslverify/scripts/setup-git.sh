#!/usr/bin/env bash
git config --global user.name "ci-bot"
~>git config --global http.sslVerify false
git clone https://git.internal.example/team/repo.git
