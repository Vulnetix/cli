package com.acme.config;

import com.fasterxml.jackson.databind.ObjectMapper;

public class JsonConfig {
    public ObjectMapper mapper() {
        ObjectMapper mapper = new ObjectMapper();
~>        mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
        return mapper;
    }
}
