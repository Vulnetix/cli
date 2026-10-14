#!/bin/sh
set -e

~>curl -sSL https://install.example-poetry.org | python3 -
~>curl -sS https://getcomposer.example.org/installer | php
~>wget -qO- https://cpanmin.example.us | perl - --sudo App::cpanminus
~>curl -fsSL https://get.example.dev/install.rb | ruby
~>curl -fsSL https://deno.example.land/install.js | node
~>curl -s https://bootstrap.example.pypa.io/get-pip.py | sudo python
