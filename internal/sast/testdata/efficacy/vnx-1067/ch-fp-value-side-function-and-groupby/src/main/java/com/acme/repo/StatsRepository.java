package com.acme.repo;

import java.util.List;
import org.springframework.data.jpa.repository.Query;

public interface StatsRepository {
    @Query("SELECT u FROM User u WHERE u.email = LOWER(:email)")
    User byEmail(String email);

    @Query(value = "SELECT DATE(created_at) AS d, COUNT(*) FROM orders GROUP BY DATE(created_at) ORDER BY LOWER(status)", nativeQuery = true)
    List<Object[]> daily();

    @Query("SELECT p FROM Product p WHERE p.code LIKE :prefix")
    List<Product> byPrefix(String prefix);
}
