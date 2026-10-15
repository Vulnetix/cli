package app;

public class Parse {
    int a(String s) { return Integer.parseInt(s, 10); }
    int b(String s) { return Integer.valueOf(s); }
    int c() { return Integer.decode("0x10"); }
    String d(String s) { return decoder.decode(s); }
}
