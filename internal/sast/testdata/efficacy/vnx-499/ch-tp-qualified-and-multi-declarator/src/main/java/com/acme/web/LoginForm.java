package com.acme.web;

import javax.persistence.Column;

public class LoginForm implements java.io.Serializable {
    private static final long serialVersionUID = 1L;

    private String username;
    @Column(name = "pwd")
~>    private String pwd;
~>    protected String clientSecret = null;
~>    private String user, password;
}
