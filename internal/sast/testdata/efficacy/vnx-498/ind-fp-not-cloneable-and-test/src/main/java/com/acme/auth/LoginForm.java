package com.acme.auth;

import java.io.Serializable;

/** Not Cloneable: password stays in this instance only. Cloneable is a bad idea here. */
public class LoginForm implements Serializable {
    private String username;
    private transient char[] password;
}
