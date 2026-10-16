package com.acme;

import javax.servlet.http.HttpServletRequest;
import org.mvel2.MVEL;

public class MvelService {
    public Object evaluate(HttpServletRequest request) {
        String formula = request.getParameter("formula");
        String wrapped = formula;
~>        return MVEL.eval(wrapped);
    }
}
