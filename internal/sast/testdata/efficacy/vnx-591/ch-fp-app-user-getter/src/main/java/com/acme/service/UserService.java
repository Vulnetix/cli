package com.acme.service;

import com.acme.model.User;

public class UserService {
    String mask(User user) {
        String raw = String.valueOf(user.getPassword());
        return raw.replaceAll(".", "*");
    }
}
