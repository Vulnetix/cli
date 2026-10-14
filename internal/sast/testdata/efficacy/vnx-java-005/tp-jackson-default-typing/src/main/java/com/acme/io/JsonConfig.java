package com.acme.io;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;

public class JsonConfig {
    public ObjectMapper legacy() {
        ObjectMapper mapper = new ObjectMapper();
~>        mapper.enableDefaultTyping();
        return mapper;
    }

    public ObjectMapper permissive() {
        ObjectMapper mapper = new ObjectMapper();
~>        mapper.activateDefaultTyping(
                LaissezFaireSubTypeValidator.instance, ObjectMapper.DefaultTyping.NON_FINAL);
        return mapper;
    }
}
