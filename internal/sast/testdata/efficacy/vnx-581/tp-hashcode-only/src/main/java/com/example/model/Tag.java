package com.example.model;

public class Tag {
    private final String name;

    public Tag(String name) {
        this.name = name;
    }

    @Override
~>    public int hashCode() {
        return name.toLowerCase().hashCode();
    }
}
