#!/bin/bash
curl -s https://api.doppler.com/v3/configs \
~>  -H "Authorization: Bearer dp.pt.@@sample:[A-Za-z0-9]{43}@@"
