package com.acme;

import org.springframework.beans.factory.annotation.Value;

public class DataSourceConfig {
~>    @Value("${spring.datasource.password:root}")
    private String password;
}
