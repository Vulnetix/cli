package com.acme.fetch;

import java.net.URL;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;

public class Cfg {
    @Value("${upstream.url}")
    private String upstream;
    private JdbcTemplate jdbcTemplate;

    public Object call() throws Exception {
        return new URL(upstream).openStream();
    }

    public void ddl() {
        jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS t (id int)");
    }
}
