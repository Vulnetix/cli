class Doc {
    // while (i < n) { total += values[i]; }  -- forgot i++ here once
    /*
     * while (i < n) {
     * }
     */
    String help = "while (i < n) { }";

    void loop(int i, int n) {
        do {
            i = step(i);
        } while (i < n);
    }
}
