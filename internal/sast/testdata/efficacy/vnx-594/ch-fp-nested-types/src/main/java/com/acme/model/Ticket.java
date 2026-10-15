package com.acme.model;

import java.io.Serializable;
import javax.persistence.Entity;
import javax.persistence.Id;

@Entity
public class Ticket implements Serializable {
    @Id
    private Long id;
    private Status status;

    public enum Status { OPEN, CLOSED }

    public static class Builder {
        private Long id;
        public Ticket build() { return new Ticket(); }
    }
}
