public final class Labels {
    static String describe(String owner) {
~>        String s = "Owner: " + owner == null ? "none" : owner;
        return s;
    }
}
