package com.acme;

import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Filters;
import org.bson.Document;

public class UserDao {
    private final MongoCollection<Document> users;
    private final MongoCollection<Document> orders;

    public UserDao(MongoCollection<Document> users, MongoCollection<Document> orders) {
        this.users = users;
        this.orders = orders;
    }

    public Document findByName(String user) {
~>        Document filter = Document.parse("{ username: '" + user + "' }");
        return users.find(filter).first();
    }

    public Iterable<Document> highLevel(String level) {
~>        return orders.find(Filters.where("this.level > " + level));
    }
}
