package com.acme.audit;

import javax.persistence.Entity;
import javax.persistence.Id;

~>@Entity public class Tag {
    @Id
    private String name;
}
