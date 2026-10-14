package com.acme.api;

import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ReportController {
    private JdbcTemplate template;

    @GetMapping("/report")
    public List<Map<String, Object>> report(@RequestParam String region) {
        String sql = String.format("SELECT * FROM sales WHERE region = '%s'", region);
~>        return template.queryForList(sql);
    }

    @GetMapping("/count")
    public Integer count(@RequestParam("table") String table) {
~>        return template.queryForObject("SELECT count(*) FROM ".concat(table), Integer.class);
    }
}
