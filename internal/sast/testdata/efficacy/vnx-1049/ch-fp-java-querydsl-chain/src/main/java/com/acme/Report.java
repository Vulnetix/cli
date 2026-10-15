package com.acme;

public class Report {
    public List<Tuple> load(JPAQueryFactory q) {
        return q.select(order.id, customer.name)
            .from(order)
            .join(order.customer, customer)
            .join(customer.region, region)
            .leftJoin(order.items, item)
            .leftJoin(item.product, product)
            .leftJoin(product.vendor, vendor)
            .fetch();
    }
}
