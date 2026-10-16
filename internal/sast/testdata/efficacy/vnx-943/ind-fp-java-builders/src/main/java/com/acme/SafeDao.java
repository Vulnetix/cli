package com.acme;

import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Filters;
import org.bson.Document;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;

public class SafeDao {
    private final MongoCollection<Document> users;

    public SafeDao(MongoCollection<Document> users) {
        this.users = users;
    }

    public Document byName(String name) {
        return users.find(Filters.eq("username", name)).first();
    }

    public Document constantWhere() {
        return users.find(Filters.where("this.balance < this.creditLimit")).first();
    }

    public Document constantParse() {
        return Document.parse("{ active: true, role: 'member' }");
    }

    public Query spring(String name) {
        return new Query(Criteria.where("username").is(name));
    }
}
