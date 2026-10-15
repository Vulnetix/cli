package com.acme.web;

import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/reports")
public class ReportController {

    private final NamedParameterJdbcTemplate namedParameterJdbcTemplate;

    public ReportController(NamedParameterJdbcTemplate t) {
        this.namedParameterJdbcTemplate = t;
    }

    @GetMapping("/{team}")
    public List<Map<String, Object>> byTeam(@PathVariable String team) {
~>        return namedParameterJdbcTemplate.queryForList(
            "SELECT * FROM reports WHERE team = :team",
            Map.of("team", team));
    }
}
