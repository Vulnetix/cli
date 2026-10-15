package com.shop.web;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class SignupRequest {
    @NotBlank
    @Size(min = 3, max = 40)
    private String username;

~>    @Size(min = 4, max = 64)
    @NotBlank
    private String password;

    public boolean weak(String rawPassword) {
~>        return rawPassword.length() < 6;
    }

    public void check(SignupRequest r) {
~>        if (r.getPassword().length() < 5) {
            throw new IllegalArgumentException("short");
        }
    }
}
