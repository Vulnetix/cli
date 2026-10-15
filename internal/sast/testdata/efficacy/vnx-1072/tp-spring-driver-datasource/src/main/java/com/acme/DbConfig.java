package com.acme;

import javax.sql.DataSource;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.SimpleDriverDataSource;

public class DbConfig {
    @Bean
    public DataSource dataSource() {
~>        DriverManagerDataSource ds = new DriverManagerDataSource();
        ds.setUrl("jdbc:h2:mem:app");
        return ds;
    }

    @Bean
    public DataSource reporting() {
~>        return new SimpleDriverDataSource(new org.h2.Driver(), "jdbc:h2:mem:rep");
    }
}
