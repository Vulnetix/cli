package com.acme;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;

public class FormController {
    private final ObjectMapper mapper = new ObjectMapper();

    public Map<String, String[]> params(HttpServletRequest request) throws Exception {
        Map<String, String[]> copy = new HashMap<>();
        copy.putAll(request.getParameterMap());
        Form form = mapper.readValue(request.getInputStream(), Form.class);
        return copy;
    }
}
