#!/bin/sh
curl -X POST "https://hooks.slack.com/services/${SLACK_TEAM}/${SLACK_BOT}/${SLACK_SECRET}" -d '{"text":"done"}'
