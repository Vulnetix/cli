package com.acme.model;

import java.io.Serializable;
import javax.persistence.Entity;
import javax.persistence.Id;

@Entity public class Label implements Serializable {
    @Id
    private String name;
}
