package com.acme.model;

@Entity
@Table(name = "users")
public class User {
    @Id
    private Long id;

    private String email;

~>    String passwordHash;
~>    String apiKey ;

    public String getEmail() { return email; }
}
