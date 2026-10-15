package com.acme.repo;

import com.mongodb.BasicDBObject;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Filters;
import org.bson.Document;

public class OrderRepo {
    private final MongoCollection<Document> orders;

    public OrderRepo(MongoCollection<Document> orders) {
        this.orders = orders;
    }

    public Iterable<Document> byOwner(String owner) {
~>        BasicDBObject q = new BasicDBObject("$where", "this.owner == '" + owner + "'");
        return orders.find(q);
    }

    public Iterable<Document> byLevel(String level) {
~>        return orders.find(Filters.where("this.level > " + level));
    }
}
