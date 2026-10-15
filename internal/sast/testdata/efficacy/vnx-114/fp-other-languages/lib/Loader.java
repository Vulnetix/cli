package lib;

public class Loader {
    static {
        System.loadLibrary("acme-native");
    }

    public static void init(String configured) {
        System.load(System.getProperty("acme.lib.path"));
    }
}
