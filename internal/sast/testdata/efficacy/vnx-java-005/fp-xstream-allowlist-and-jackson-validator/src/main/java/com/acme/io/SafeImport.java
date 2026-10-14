package com.acme.io;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import com.thoughtworks.xstream.XStream;

public class SafeImport {
    public Object parse(String payload) {
        XStream xstream = new XStream();
        xstream.allowTypes(new Class[] {Contact.class});
        return xstream.fromXML(payload);
    }

    public ObjectMapper mapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.activateDefaultTyping(
                BasicPolymorphicTypeValidator.builder().allowIfBaseType(Contact.class).build(),
                ObjectMapper.DefaultTyping.NON_FINAL);
        return mapper;
    }
}
