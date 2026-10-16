package zoo;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

@JsonTypeInfo(use = JsonTypeInfo.Name.NAME, property = "kind")
@JsonSubTypes({
    @JsonSubTypes.Type(value = Dog.class, name = "dog")
})
public abstract class Animal {
    public abstract String sound();
}
