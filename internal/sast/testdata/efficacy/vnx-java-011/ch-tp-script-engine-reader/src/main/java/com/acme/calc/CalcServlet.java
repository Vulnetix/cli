package com.acme.calc;

import java.io.StringReader;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CalcServlet {
    private final ScriptEngine js = new ScriptEngineManager().getEngineByName("nashorn");

    @PostMapping("/calc")
    public Object calc(@RequestBody String formula) throws Exception {
        String wrapped = "(function(){ return " + formula + "; })()";
~>        return js.eval(new StringReader(wrapped));
    }
}
