#!/bin/sh
~>poetry config pypi-token.pypi pypi-AgEIcHlwaS5vcmc@@sample:[A-Za-z0-9_-]{100}@@
poetry publish --build
