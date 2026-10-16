package com.acme.api;

import com.fasterxml.jackson.annotation.JsonIgnore;
import javax.persistence.Entity;
import javax.persistence.Id;

@Entity
public class User {
    @Id
    private Long id;
    private String login;

    @JsonIgnore
    private String password;

    public Long getId() { return id; }
    public String getLogin() { return login; }
    public String getPassword() { return password; }
}
