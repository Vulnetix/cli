package notify

import "os"

// docs: https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX
const example = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"

var hook = os.Getenv("SLACK_WEBHOOK_URL")
var base = "https://hooks.slack.com/services/"
var partial = "https://hooks.slack.com/services/T4Q7ZK2M9/B07H3RJ5WQ2"
