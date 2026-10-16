#!/bin/sh
~>mvn -B sonar:sonar -Dsonar.login='@@sample:sqa_[a-f0-9]{40}@@'
