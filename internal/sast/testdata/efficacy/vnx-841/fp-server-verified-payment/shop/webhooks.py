from flask import request


@app.post("/webhooks/stripe")
def webhook():
    event = stripe.Webhook.construct_event(request.data, request.headers["Stripe-Signature"], SECRET)
    if event["type"] == "checkout.session.completed":
        order = Order.query.filter_by(session_id=event["data"]["object"]["id"]).one()
        order.status = OrderStatus.PAID
        db.session.commit()
    return "", 200
