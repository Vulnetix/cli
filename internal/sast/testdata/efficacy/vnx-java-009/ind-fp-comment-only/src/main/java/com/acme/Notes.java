package com.acme;

public class Notes {
    // Never do: new File(base, request.getParameter("file")) - allows ../ traversal
    /* Paths.get(root + request.getParameter("p")) is vulnerable too */
    String doc = "new FileInputStream(request.getParameter(\"x\"))";
}
