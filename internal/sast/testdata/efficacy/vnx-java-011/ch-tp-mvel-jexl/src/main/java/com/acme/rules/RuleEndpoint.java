package com.acme.rules;

import java.io.Serializable;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import @@sample:o[r]g[.][a]pa[c]he[.]co[m]mo[n]s[.][j]ex[l]3[.][J]ex[l]Bu[i]ld[e]r@@;
import @@sample:o[r]g[.][a]pa[c]he[.]co[m]mo[n]s[.][j]ex[l]3[.][J]ex[l]En[g]in[e]@@;
import @@sample:o[r]g[.][a]pa[c]he[.]co[m]mo[n]s[.][j]ex[l]3[.][J]ex[l]Ex[p]re[s]si[o]n@@;
import @@sample:o[r]g[.][a]pa[c]he[.]co[m]mo[n]s[.][j]ex[l]3[.][M]ap[C]on[t]ex[t]@@;
import org.mvel2.MVEL;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RuleEndpoint {
    private final JexlEngine jexl = new JexlBuilder().create();

    @PostMapping("/rules/mvel")
    public Object mvel(@RequestParam("condition") String condition, Map<String, Object> facts) {
~>        Serializable compiled = MVEL.compileExpression(condition);
        return MVEL.executeExpression(compiled, facts);
    }

    @PostMapping("/rules/jexl")
    public Object jexl(HttpServletRequest request) {
~>        JexlExpression e = jexl.createExpression(
            request.getParameter("q"));
        return e.evaluate(new MapContext());
    }
}
