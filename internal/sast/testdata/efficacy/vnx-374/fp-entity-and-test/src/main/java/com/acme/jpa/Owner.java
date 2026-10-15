package com.acme.jpa;

import jakarta.persistence.Entity;
import jakarta.persistence.OneToMany;
import java.util.List;

@Entity
public class Owner {
    @OneToMany
    private List<Pet> pets;

    public void setPets(List<Pet> pets) {
        this.pets = pets;
    }
}
