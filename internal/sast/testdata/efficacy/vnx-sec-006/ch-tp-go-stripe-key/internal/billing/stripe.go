package billing

import "github.com/stripe/stripe-go/v76"

func init() {
~>	stripe.Key = "@@sample:sk_live_[A-Za-z0-9]{24}@@"
}
