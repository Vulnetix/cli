import json
import logging

from django.contrib import messages
from django.db import transaction
from django.http import HttpResponseBadRequest, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render

from . import audit, emails, fraud, inventory, payments, pricing, shipping, tax
from .forms import CheckoutForm
from .models import Cart, Coupon, Order

log = logging.getLogger(__name__)


~>def checkout(request, cart_id):
    cart = get_object_or_404(Cart, pk=cart_id, owner=request.user)
    form = CheckoutForm(request.POST or None)
    if request.method != "POST":
        return render(request, "shop/checkout.html", {"form": form, "cart": cart})
    if not form.is_valid():
        messages.error(request, "Please correct the errors below.")
        return render(request, "shop/checkout.html", {"form": form, "cart": cart})

    data = form.cleaned_data
    items = cart.items.select_related("product").all()
    if not items.exists():
        return HttpResponseBadRequest("empty cart")

    coupon = None
    if data.get("coupon"):
        coupon = Coupon.objects.filter(code=data["coupon"]).first()
        if coupon and not coupon.is_active():
            messages.warning(request, "That coupon has expired.")
            coupon = None

    subtotal = pricing.subtotal(items)
    discount = pricing.apply_coupon(subtotal, coupon)
    rate = tax.rate_for(data["country"], data["postcode"])
    tax_due = tax.compute(subtotal - discount, rate)
    quote = shipping.quote(items, data["country"], speed=data["speed"])

    score = fraud.score(request.user, request.META.get("REMOTE_ADDR"), subtotal)
    if fraud.should_block(score):
        audit.record("checkout.blocked", user=request.user, score=score)
        log.warning("blocked checkout for %s", request.user.pk)
        return redirect("shop:review")

    with transaction.atomic():
        for item in items:
            inventory.reserve(item.product, item.quantity)
        order = Order.objects.create(
            owner=request.user,
            subtotal=subtotal,
            discount=discount,
            tax=tax_due,
            shipping=quote.amount,
        )
        order.lines.bulk_create(pricing.order_lines(order, items))
        charge = payments.charge(
            data["card_token"],
            amount=order.total(),
            idempotency_key=str(order.uuid),
        )
        if not charge.ok:
            transaction.set_rollback(True)
            inventory.release_all(items)
            messages.error(request, charge.message)
            return redirect("shop:checkout", cart_id=cart.pk)
        order.mark_paid(charge.reference)
        cart.clear()

    shipping.schedule(order, quote)
    emails.send_receipt(order, request.user.email)
    emails.notify_warehouse(order)
    audit.record("checkout.paid", user=request.user, order=order.pk)
    log.info("order %s paid", order.pk)
    request.session.pop("cart_id", None)
    request.session.modified = True

    if request.headers.get("Accept") == "application/json":
        payload = json.dumps({"order": str(order.uuid)})
        return JsonResponse(json.loads(payload))
    messages.success(request, "Thank you, your order is on its way.")
    return redirect("shop:order", order_id=order.pk)
