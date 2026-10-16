package com.acme.repo;

import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.RequestParam;

public class ReportRepo {
    private final JdbcTemplate jdbcTemplate;

    public ReportRepo(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public List<Map<String, Object>> byRegion(@RequestParam String region) {
        String sql = String.format("SELECT * FROM sales WHERE region = '%s'", region);
~>        return jdbcTemplate.queryForList(sql);
    }
}
