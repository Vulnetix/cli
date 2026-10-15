package com.acme.json;

import java.io.InputStream;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;

public class PayloadParser {
    public JsonObject parse(InputStream in) {
        try (JsonReader reader = Json.createReader(in)) {
            JsonObject obj = reader.readObject();
            return obj;
        }
    }
}
