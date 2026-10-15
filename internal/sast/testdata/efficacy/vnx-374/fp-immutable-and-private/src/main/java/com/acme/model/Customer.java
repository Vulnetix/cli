package com.acme.model;

import com.google.common.collect.ImmutableList;
import java.util.List;

public class Customer {
    private String name;
    private int age;
    private ImmutableList<String> roles;
    private List<String> aliases;

    public void setName(String name) {
        this.name = name;
    }

    public void setAge(int age) {
        this.age = age;
    }

    public void setRoles(ImmutableList<String> roles) {
        this.roles = roles;
    }

    private void setAliases(List<String> aliases) {
        this.aliases = aliases;
    }

    public void rename(List<String> names) {
        String first = names.get(0);
        this.name = first;
    }
}
