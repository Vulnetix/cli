using Stripe;

public class Startup
{
    public void Configure()
    {
~>        StripeConfiguration.ApiKey = "@@sample:sk_live_[A-Za-z0-9]{99}@@";
    }
}
