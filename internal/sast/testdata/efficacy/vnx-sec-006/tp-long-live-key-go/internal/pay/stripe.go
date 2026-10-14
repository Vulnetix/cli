package pay

import "github.com/stripe/stripe-go/v76"

func init() {
~>	stripe.Key = "@@sample:sk_live_51[0-9a-zA-Z]{97}@@"
}
