package com.acme;
import javax.sql.DataSource;
import org.springframework.context.annotation.*;
import org.springframework.jdbc.datasource.*;
@Configuration
public class Config {
    @Bean DataSource main() {
~>        DriverManagerDataSource ds = new DriverManagerDataSource();
        ds.setUrl("jdbc:h2:mem:x");
        return ds;
    }
    @Bean DataSource second() {
~>        return new SimpleDriverDataSource(new org.h2.Driver(), "jdbc:h2:mem:y");
    }
}
