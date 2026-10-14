package com.acme.rules;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.servlet.http.HttpServletRequest;

public class Bootstrap {
    void init(HttpServletRequest request) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("nashorn");
        String user = request.getParameter("user");
        engine.put("user", user);
        engine.eval(loadBundledScript("init.js"));
        engine.eval("greet(user)");
    }

    String loadBundledScript(String name) {
        return "";
    }
}
