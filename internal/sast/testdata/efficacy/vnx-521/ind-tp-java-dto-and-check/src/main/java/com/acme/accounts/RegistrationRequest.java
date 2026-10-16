package com.acme.accounts;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class RegistrationRequest {

    @NotBlank
    @Email
    private String email;

    @NotBlank
~>    @Size(min = 6, max = 72)
    private String password;

    public String getEmail() { return email; }
    public String getPassword() { return password; }

    public boolean isAcceptable() {
~>        if (password.length() < 5) {
            return false;
        }
        return !password.equalsIgnoreCase(email);
    }
}
