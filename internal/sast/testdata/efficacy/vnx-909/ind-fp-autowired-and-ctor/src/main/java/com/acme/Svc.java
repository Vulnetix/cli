package com.acme;

import org.springframework.beans.factory.annotation.Autowired;

public class Svc {
    @Autowired
    private UserRepository users;
    private DataSource ds;

    public Svc(DataSource ds) {
        this.ds = ds;
    }

    public Object one(long id) throws Exception {
        ds.getConnection();
        return users.findById(id);
    }
}
