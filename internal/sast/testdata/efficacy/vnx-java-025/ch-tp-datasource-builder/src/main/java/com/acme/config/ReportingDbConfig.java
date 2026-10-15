package com.acme.config;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import javax.sql.DataSource;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ReportingDbConfig {

    @Bean
    public DataSource reportingDataSource() {
        return DataSourceBuilder.create()
                .url("jdbc:postgresql://reports.internal:5432/reports")
                .username("report_svc")
~>                .password("Rep0rt!ng-2023")
                .build();
    }

    @Bean
    public DataSource auditDataSource() {
        HikariConfig cfg = new HikariConfig();
        cfg.setJdbcUrl("jdbc:mysql://audit.internal:3306/audit");
        cfg.setUsername("auditor");
~>        cfg.setPassword("hik4riS3cret");
        cfg.setMaximumPoolSize(4);
        return new HikariDataSource(cfg);
    }
}
