package com.acme.api;

import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.PathVariable;

@Controller("/users")
public class UserV1Controller {

    private final UserService users;

    public UserV1Controller(UserService users) {
        this.users = users;
    }

~>    @Deprecated
    @Get("/v1/{id}")
    public UserDto findV1(@PathVariable String id) {
        return users.findWithoutAcl(id);
    }
}
