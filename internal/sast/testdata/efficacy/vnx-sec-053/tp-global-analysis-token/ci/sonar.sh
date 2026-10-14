#!/bin/sh
mvn -B verify sonar:sonar \
~>  -Dsonar.login='sqa_@@sample:[a-f0-9]{40}@@' \
  -Dsonar.host.url=https://sonar.acme.internal
