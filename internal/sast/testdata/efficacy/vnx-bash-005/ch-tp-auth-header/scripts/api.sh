#!/bin/bash
~>curl -s -H "Authorization: Bearer @@sample:[A-Za-z0-9]{40}@@" https://api.example.org/v1/items
~>curl -s -H 'X-Api-Key: @@sample:[a-f0-9]{32}@@' https://api.example.org/v1/items
