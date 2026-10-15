package com.acme.bank;

public class Notes {
    // synchronized (a) { synchronized (b) { ... } } in one place and
    // synchronized (b) { synchronized (a) { ... } } in another deadlocks.
    /*
     * synchronized (b) {
     *     synchronized (a) {
     *     }
     * }
     */
    static final String HELP = "never write synchronized (a) { synchronized (b) {} } then the reverse";

    void ok() {
        synchronized (a) {
            work();
        }
    }
}
