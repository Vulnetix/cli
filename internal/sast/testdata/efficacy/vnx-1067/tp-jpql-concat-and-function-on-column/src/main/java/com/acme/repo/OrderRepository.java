package com.acme.repo;

public interface OrderRepository extends JpaRepository<Order, Long> {
~>    @Query("SELECT o FROM Order o WHERE o.reference LIKE CONCAT('%', :ref, '%')")
    List<Order> findByReference(@Param("ref") String ref);

~>    @Query(value = "SELECT * FROM orders WHERE LOWER(customer_email) = LOWER(:email)", nativeQuery = true)
    List<Order> findByEmail(@Param("email") String email);

    @Query(value = "SELECT * FROM orders WHERE " +
~>            "UPPER(status) LIKE UPPER(:s)", nativeQuery = true)
    List<Order> byStatus(@Param("s") String s);
}
