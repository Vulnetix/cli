package com.acme;

import com.stripe.Stripe;

public class Billing {
    static {
~>        Stripe.apiKey = "@@sample:sk_live_[A-Za-z0-9]{24}@@";
    }
}
