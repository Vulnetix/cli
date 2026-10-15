package com.acme.events;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type")
@JsonSubTypes({
    @JsonSubTypes.Type(value = OrderPlaced.class, name = "placed"),
    @JsonSubTypes.Type(value = OrderShipped.class, name = "shipped")
})
public abstract class Event {
    private String id;

    public String getId() {
        return id;
    }
}
