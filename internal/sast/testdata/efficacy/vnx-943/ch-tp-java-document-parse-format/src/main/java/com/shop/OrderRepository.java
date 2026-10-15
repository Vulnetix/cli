package com.shop;

import com.mongodb.client.MongoCollection;
import org.bson.Document;
import javax.servlet.http.HttpServletRequest;

public class OrderRepository {
    private final MongoCollection<Document> orders;

    public OrderRepository(MongoCollection<Document> orders) {
        this.orders = orders;
    }

    public Document find(HttpServletRequest req) {
        String customer = req.getParameter("customer");
~>        Document filter = Document.parse(String.format("{customer: '%s'}", customer));
        return orders.find(filter).first();
    }
}
