package com.acme.gen;

public final class Template {
    static final String BODY = "try { run(); } catch (Exception e) {}";

    // An empty block such as catch (Exception e) {} hides errors.
    String render() {
        return BODY.replace("run", "go");
    }
}
