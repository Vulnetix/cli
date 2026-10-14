package com.acme.rules;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.ws.rs.POST;
import javax.ws.rs.QueryParam;
import org.mvel2.MVEL;

public class RuleRunner {
    private final ScriptEngine engine = new ScriptEngineManager().getEngineByName("javascript");

    @POST
    public Object run(@QueryParam("script") String script, @QueryParam("rule") String rule) throws Exception {
~>        Object result = engine.eval(script);
~>        Object mv = MVEL.eval(rule, new java.util.HashMap<String, Object>());
        return result;
    }
}
