package com.acme.model;

import java.io.Serializable;

public class AccountSettings implements Serializable {
    private static final long serialVersionUID = 1L;
    private static final String PASSWORD_PARAM = "password";
    private transient String password;
    private transient char[] sessionToken;
    private String passwordPolicy;
    private int passwordLength;
    private String tokenEndpoint;
    private boolean pinEnabled;
}
