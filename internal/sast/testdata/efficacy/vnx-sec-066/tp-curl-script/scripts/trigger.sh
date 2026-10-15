#!/bin/sh
~>curl -s -H 'Authorization: Bearer @@sample:[A-Za-z0-9]{40}@@' https://ci.acme-corp.io/api/v4/trigger
