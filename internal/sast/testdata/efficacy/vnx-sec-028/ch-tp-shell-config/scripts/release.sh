#!/usr/bin/env bash
~>npm config set //registry.npmjs.org/:_authToken npm_@@sample:[A-Za-z0-9]{36}@@
npm publish --access public
