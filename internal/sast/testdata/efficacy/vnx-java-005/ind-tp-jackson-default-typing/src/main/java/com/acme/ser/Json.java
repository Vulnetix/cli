package com.acme.ser;

import com.fasterxml.jackson.databind.ObjectMapper;

public class Json {
    public ObjectMapper mapper() {
        ObjectMapper mapper = new ObjectMapper();
~>        mapper.enableDefaultTyping();
        return mapper;
    }
}
