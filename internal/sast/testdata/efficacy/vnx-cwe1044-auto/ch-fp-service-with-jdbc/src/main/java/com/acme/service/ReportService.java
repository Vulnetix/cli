package com.acme.service;

import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/** Data access for reports; the ReportController calls this service. */
@Service
public class ReportService {

    private final JdbcTemplate jdbcTemplate;

    public ReportService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public List<Map<String, Object>> byTeam(String team) {
        return jdbcTemplate.queryForList("SELECT * FROM reports WHERE team = ?", team);
    }
}
