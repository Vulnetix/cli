package com.shop;

import com.mongodb.BasicDBObject;
import com.mongodb.DBCollection;
import com.mongodb.DBCursor;

public class UserDao {
    private final DBCollection users;

    public UserDao(DBCollection users) {
        this.users = users;
    }

    public DBCursor byName(String name) {
~>        BasicDBObject q = new BasicDBObject("$where", "this.name == '" + name + "'");
        return users.find(q);
    }
}
