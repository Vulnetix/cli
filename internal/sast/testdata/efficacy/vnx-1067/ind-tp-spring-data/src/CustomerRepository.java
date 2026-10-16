package repo;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface CustomerRepository extends JpaRepository<Customer, Long> {
~>    List<Customer> findByLastNameContainingIgnoreCase(String fragment);

~>    @Query(value = "SELECT * FROM orders WHERE LOWER(customer_email) = LOWER(:email)", nativeQuery = true)
    List<Order> byEmail(String email);

    List<Customer> findByLastNameStartingWith(String p);
}
