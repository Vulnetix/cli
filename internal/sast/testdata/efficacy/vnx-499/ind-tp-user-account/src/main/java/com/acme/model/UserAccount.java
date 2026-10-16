package com.acme.model;

import java.io.Serializable;

public class UserAccount implements Serializable {
    private static final long serialVersionUID = 42L;
    private String username;
~>    private String password;
~>    private char[] pin;
    private String email;

    public String getUsername() { return username; }
}
