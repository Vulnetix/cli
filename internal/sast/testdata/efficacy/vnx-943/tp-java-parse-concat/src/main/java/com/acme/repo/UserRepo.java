package com.acme.repo;

import org.bson.Document;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.BasicQuery;

public class UserRepo {
    private final MongoTemplate mongo;

    public UserRepo(MongoTemplate mongo) {
        this.mongo = mongo;
    }

    public Object login(String user, String pass) {
~>        Document filter = Document.parse("{ username: '" + user + "', password: '" + pass + "' }");
        return mongo.getCollection("users").find(filter).first();
    }

    public Object byName(String name) {
        String json = "{ \"name\": \"" + name + "\" }";
~>        return mongo.find(new BasicQuery(json), Object.class);
    }

    public Object byRole(String role) {
~>        return mongo.findOne(new BasicQuery(String.format("{ role: '%s' }", role)), Object.class);
    }
}
