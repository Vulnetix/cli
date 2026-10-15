package com.acme.model;

public class User {
    private String name;
    private int age;

~>    public String getName() { return getName(); }

    public int getAge() {
~>        return this.getAge();
    }
}
