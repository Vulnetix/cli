#!/bin/sh
~>curl https://api.stripe.com/v1/refunds -u @@sample:sk_live_[A-Za-z0-9]{24}@@: -d charge="$1"
