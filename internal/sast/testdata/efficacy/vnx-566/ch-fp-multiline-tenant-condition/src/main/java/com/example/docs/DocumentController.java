package com.example.docs;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DocumentController {
    private final JdbcTemplate jdbc;
    private final TenantContext tenants;

    public DocumentController(JdbcTemplate jdbc, TenantContext tenants) {
        this.jdbc = jdbc;
        this.tenants = tenants;
    }

    @GetMapping("/documents/{docId}")
    public Document get(@PathVariable String docId) {
        String sql = "SELECT id, title, body FROM documents "
            + "WHERE doc_id = ? "
            + "AND tenant_id = ?";
        return jdbc.queryForObject(sql, new DocumentMapper(), docId, tenants.current());
    }
}
