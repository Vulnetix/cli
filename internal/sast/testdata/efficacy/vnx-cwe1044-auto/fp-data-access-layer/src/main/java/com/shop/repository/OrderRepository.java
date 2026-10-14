package com.shop.repository;

@Repository
public class OrderRepository {
    private final JdbcTemplate jdbcTemplate;

    public List<Map<String, Object>> salesByRegion() {
        return jdbcTemplate.queryForList("SELECT region, SUM(total) FROM orders GROUP BY region");
    }
}
