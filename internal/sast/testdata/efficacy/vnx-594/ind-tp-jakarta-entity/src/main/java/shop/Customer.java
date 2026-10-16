package shop;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;

@Entity
~>public class Customer {
    @Id
    private Long id;
    private String name;
}
