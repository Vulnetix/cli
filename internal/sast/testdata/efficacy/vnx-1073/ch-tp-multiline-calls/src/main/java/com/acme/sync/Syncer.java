package com.acme.sync;

import org.springframework.jdbc.core.JdbcTemplate;

public class Syncer {
    private final JdbcTemplate jdbcTemplate;

    public Syncer(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

~>    public void sync(
            long tenant,
            String region) {
        jdbcTemplate
            .update("delete from stage where tenant = ?", tenant);
        jdbcTemplate.update(
            "insert into stage select * from src where tenant = ?", tenant);
        Integer n = jdbcTemplate.queryForObject(
            "select count(*) from stage where tenant = ?", Integer.class, tenant);
        jdbcTemplate.update("update tenants set rows = ? where id = ?", n, tenant);
        jdbcTemplate.execute("analyze stage");
    }
}
