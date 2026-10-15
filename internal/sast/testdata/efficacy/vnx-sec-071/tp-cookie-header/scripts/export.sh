#!/bin/sh
~>curl -s -H "Cookie: _gitlab_session=@@sample:[0-9a-f]{32}@@" https://gitlab.acme-corp.io/api/v4/projects
