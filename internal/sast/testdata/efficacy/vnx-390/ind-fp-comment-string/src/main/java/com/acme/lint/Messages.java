package com.acme.lint;

public final class Messages {
    // Bad: } catch (Exception e) {}
    public static final String EMPTY_CATCH = "catch (Exception e) {} swallows the failure";

    private Messages() {}
}
