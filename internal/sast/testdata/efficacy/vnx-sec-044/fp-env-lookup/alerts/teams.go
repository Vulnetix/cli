package alerts

import "os"

var url = os.Getenv("TEAMS_WEBHOOK_URL") // e.g. https://<tenant>.webhook.office.com/webhookb2/<id>/IncomingWebhook/<id>/<id>
