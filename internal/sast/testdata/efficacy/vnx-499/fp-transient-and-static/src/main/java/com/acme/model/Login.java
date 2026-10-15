package com.acme.model;

import java.io.Serializable;

public class Login implements Serializable {
    private static final String PASSWORD_PARAM = "password";
    private transient String password;
    private transient char[] secret;
    private String passwordPolicy;
    private int passwordLength;
    private boolean passwordRequired;
    private String tokenEndpoint;
    // private String apiKey;
}
