package com.acme.rules;

import java.io.InputStreamReader;
import java.io.Reader;
import javax.script.Bindings;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import javax.servlet.http.HttpServletRequest;

public class ScriptedPricing {
    private final ScriptEngine engine = new ScriptEngineManager().getEngineByName("graal.js");

    public Object price(HttpServletRequest request) throws ScriptException {
        Bindings bindings = engine.createBindings();
        bindings.put("quantity", request.getParameter("qty"));
        bindings.put("sku", request.getParameter("sku"));
        Reader script = new InputStreamReader(getClass().getResourceAsStream("/pricing.js"));
        return engine.eval(script, bindings);
    }
}
