import stripe
from stripe import StripeClient

client = StripeClient(settings.STRIPE_KEY)


def payout(seller):
~>    stripe.Transfer.create(
        amount=seller.balance,
        currency="usd",
        destination=seller.account_id,
    )


def intent(order):
~>    return @@sample:c[l]ie[n]t[.][v]1[.][p]ay[m]en[t][_]i[n]te[n]ts[.]cr[e]at[e]@@(
        params={"amount": order.total, "currency": "usd"},
    )
