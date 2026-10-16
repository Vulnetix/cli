package ok;

import java.util.List;
import java.util.Map;

public class Ok {
    public void seven(String a, int b, long c, Map<String, List<Integer>> d,
                      boolean e, double f, char g) { }

    public void generics(Map<String, Integer> m, Map<Integer, Map<String, String>> n) { }

    public void varargs(String a, String b, String c, String d, String e, String f, String... rest) { }

    public void caller() {
        seven("a", 1, 2L, null, true, 1.0, 'c');
        Object o = new Object[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    }
}
