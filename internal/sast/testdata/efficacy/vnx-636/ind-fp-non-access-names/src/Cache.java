package app;

public class Cache {
    public boolean fileExists(String p) {
        try {
            return stat(p);
        } catch (Exception e) {
            return true;
        }
    }

    boolean isNumeric(String s) {
        try {
            Integer.parseInt(s);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}
