#!/bin/bash

~>bash <(curl -fsSL https://get.example.com/install.sh)
~>sudo bash -c "$(curl --fail --show-error --silent --location https://raw.githubusercontent.com/example/setup/main/install.sh)"
~>sh -c "$(wget -qO- https://install.example.dev/ohmy.sh)"
~>source <(curl -s https://example.com/env.sh)
~>. <(wget -qO- https://example.com/functions.sh)
~>eval "$(curl -fsSL https://example.com/shellenv)"
~>/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/example/install/HEAD/install.sh)"
