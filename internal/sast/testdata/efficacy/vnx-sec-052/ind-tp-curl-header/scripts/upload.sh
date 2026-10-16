#!/bin/bash
~>curl -H "X-JFrog-Art-Api: @@sample:AKCp[A-Za-z0-9]{69}@@" -T app.jar \
  https://acme.jfrog.io/artifactory/libs-release/app.jar
