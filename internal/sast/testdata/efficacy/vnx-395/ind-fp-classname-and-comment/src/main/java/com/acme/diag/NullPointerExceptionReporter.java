package com.acme.diag;

// Older versions used catch (NullPointerException e) here; we now check for null.
public class NullPointerExceptionReporter {
    private static final String HINT = "do not catch (NullPointerException e) to test for null";

    public String describe(Object value) {
        if (value == null) {
            return "value was null";
        }
        return value.toString();
    }

    public String hint() {
        return HINT;
    }
}
