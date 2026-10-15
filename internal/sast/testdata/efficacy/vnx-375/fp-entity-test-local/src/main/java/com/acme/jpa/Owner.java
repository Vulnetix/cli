package com.acme.jpa;

import jakarta.persistence.Entity;
import java.util.ArrayList;
import java.util.List;

@Entity
public class Owner {
    private List<Pet> pets = new ArrayList<>();

    public List<Pet> getPets() {
        return this.pets;
    }
}
