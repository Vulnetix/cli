package com.acme.repo;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CustomerRepository extends JpaRepository<Customer, Long> {
~>    List<Customer> findByLastNameContainingIgnoreCase(String fragment);

~>    List<Customer> findByEmailEndingWith(String domain);

    List<Customer> findByLastName(String lastName);
}
