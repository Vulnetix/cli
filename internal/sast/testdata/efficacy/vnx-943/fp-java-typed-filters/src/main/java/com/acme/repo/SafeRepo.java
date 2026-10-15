package com.acme.repo;

import static com.mongodb.client.model.Filters.eq;

import com.mongodb.BasicDBObject;
import com.mongodb.client.MongoCollection;
import org.bson.Document;
import org.springframework.data.mongodb.repository.Query;

public class SafeRepo {
    private final MongoCollection<Document> users;

    public SafeRepo(MongoCollection<Document> users) {
        this.users = users;
    }

    @Query("{ 'username' : ?0 }")
    public Document byName(String name) {
        return users.find(eq("username", name)).first();
    }

    public Iterable<Document> overdue() {
        BasicDBObject q = new BasicDBObject("$where", "this.due < this.paid");
        Document fixed = Document.parse("{ status: 'open' }");
        // Document.parse("{ username: '" + user + "' }") is how not to do it
        return users.find(q);
    }
}
