package com.example.config;

public class Notes {
    // props.load(getClass().getResourceAsStream("/a.properties")) may NPE
    /* getClass().getResource("/x").toURI() */
    String hint = "use getResourceAsStream(\"/x\").read() carefully";
}
