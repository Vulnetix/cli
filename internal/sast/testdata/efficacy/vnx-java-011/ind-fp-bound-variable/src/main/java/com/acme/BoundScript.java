package com.acme;

import javax.script.*;
import javax.servlet.http.HttpServletRequest;

public class BoundScript {
    public Object run(HttpServletRequest request) throws ScriptException {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        Bindings b = engine.createBindings();
        b.put("amount", request.getParameter("amount"));
        return engine.eval("amount.length * 2", b);
    }
}
