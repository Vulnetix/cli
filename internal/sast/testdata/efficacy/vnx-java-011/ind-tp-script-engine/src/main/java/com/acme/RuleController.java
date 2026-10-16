package com.acme;

import javax.script.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class RuleController {
    @PostMapping("/rules/run")
    public Object run(@RequestParam String script) throws ScriptException {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("nashorn");
~>        return engine.eval(script);
    }
}
