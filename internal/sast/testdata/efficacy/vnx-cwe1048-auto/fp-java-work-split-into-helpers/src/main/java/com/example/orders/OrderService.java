package com.example.orders;

public class OrderService {

    public Order place(Cart cart, Customer customer) {
        validate(cart, customer);
        Quote quote = price(cart, customer);
        Order order = persist(cart, customer, quote);
        notifyParties(order, customer);
        return order;
    }

    private void validate(Cart cart, Customer customer) {
        requireNonEmpty(cart.items());
        requireActive(customer.status());
        limits.check(customer.id(), cart.total());
        fraud.screen(customer.id(), cart.fingerprint());
        inventory.assertAvailable(cart.skus());
        addresses.verify(customer.shippingAddress());
        compliance.screen(customer.country());
        sanctions.check(customer.name());
        age.verify(customer.birthDate(), cart.restrictedItems());
        payments.preauthorise(customer.paymentMethod(), cart.total());
    }

    private Quote price(Cart cart, Customer customer) {
        Money subtotal = pricing.subtotal(cart.items());
        Money discount = coupons.apply(cart.coupon(), subtotal);
        Money tax = taxes.compute(customer.address(), subtotal.minus(discount));
        Money shipping = carriers.quote(cart.weight(), customer.shippingAddress());
        Money duty = customs.duty(customer.country(), cart.hsCodes());
        Money fee = fees.handling(cart.size());
        Money loyalty = rewards.redeem(customer.id(), cart.points());
        Money rounding = currency.round(subtotal, customer.currency());
        Money insurance = insurer.premium(cart.declaredValue());
        return Quote.of(subtotal, discount, tax, shipping, duty, fee, loyalty, rounding, insurance);
    }

    private Order persist(Cart cart, Customer customer, Quote quote) {
        Order order = Order.create(customer.id(), quote.total());
        order.addLines(cart.items());
        orders.save(order);
        inventory.reserve(cart.skus());
        ledger.post(order.id(), quote.total());
        invoices.issue(order.id());
        shipments.book(order.id(), customer.shippingAddress());
        warehouse.pick(order.id());
        analytics.track("order", order.id());
        return order;
    }

    private void notifyParties(Order order, Customer customer) {
        mailer.confirm(customer.email(), order.id());
        sms.send(customer.phone(), order.reference());
        webhooks.fire("order.placed", order.id());
        crm.update(customer.id(), order.total());
        partners.notify(order.affiliate());
        slack.post("#orders", order.summary());
        push.notify(customer.deviceToken(), order.reference());
        audit.log(customer.id(), "order.placed");
        metrics.increment("orders.placed");
        search.index(order);
    }
}
