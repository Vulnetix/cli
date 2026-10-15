package com.acme.user;

import com.fasterxml.jackson.annotation.JsonIgnore;
import java.io.Serializable;

public class UserProfile implements Serializable {
    private static final long serialVersionUID = 7L;
    public static final String PASSWORD_FIELD = "password";

    private String displayName;
    @JsonIgnore
    private transient String password;
    private transient @JsonIgnore char[] pin;
    private String passwordResetUrl;
    private int tokenTtlSeconds;
    private boolean secretQuestionEnabled;
}
