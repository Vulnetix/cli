#!/bin/sh
~>curl "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=AIza@@sample:[A-Za-z0-9]{35}@@" \
  -H 'Content-Type: application/json' -d '{"contents":[{"parts":[{"text":"hi"}]}]}'
