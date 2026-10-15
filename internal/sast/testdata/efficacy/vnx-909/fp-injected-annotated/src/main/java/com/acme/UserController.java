package com.acme;

import javax.inject.Inject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

public class UserController {
    @Autowired
    private UserRepository users;

    @Inject private AuditLog audit;

    @Value("${app.base-url}")
    private String baseUrl;

    public String show(String id) {
        audit.record(id);
        return baseUrl.concat("/users/") + users.find(id).getName();
    }
}
