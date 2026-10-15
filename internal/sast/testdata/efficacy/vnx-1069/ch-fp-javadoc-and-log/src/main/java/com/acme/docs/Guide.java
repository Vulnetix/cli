package com.acme.docs;

/**
 * Never write
 *     try { work(); } catch (Exception e) {}
 * because the failure disappears.
 */
public class Guide {
    public String example() {
        return "try { x(); } catch (Exception e) {}";
    }
    // catch (Exception e) {}
}
