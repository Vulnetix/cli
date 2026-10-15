package com.acme.doc;

public class Snippets {
    // Avoid writing: try { work(); } catch (Exception e) {}
    static final String BAD = "try { work(); } catch (Exception e) {}";

    /*
     * } catch (Exception e) {
     * }
     */
    public String bad() {
        return BAD;
    }
}
