#!/bin/sh
~>curl -s -H "Cookie: _gitlab_session=@@sample:[a-f0-9]{32}@@" https://gitlab.acme-corp.io/api/v4/projects
