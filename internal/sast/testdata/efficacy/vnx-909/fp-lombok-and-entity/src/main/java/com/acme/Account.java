package com.acme;

import javax.persistence.Entity;
import javax.persistence.Id;

@Entity
public class Account {
    @Id
    private Long id;
    private String email;

    public String domain() {
        return email.substring(email.indexOf('@') + 1);
    }
}
