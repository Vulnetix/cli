#!/bin/sh
~>curl https://payments.acme-corp.io/v1/charges -u @@sample:[A-Za-z0-9]{32}@@: -d amount=2000
