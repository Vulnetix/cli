package com.acme.account;

import com.google.common.collect.ImmutableList;
import java.time.Instant;

public class Profile {
    private String displayName;
    private int age;
    private ImmutableList<String> roles;
    private Instant createdAt;

    public Profile(String displayName, int age, ImmutableList<String> roles, Instant createdAt) {
        this.displayName = displayName;
        this.age = age;
        this.roles = roles;
        this.createdAt = createdAt;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }
}
