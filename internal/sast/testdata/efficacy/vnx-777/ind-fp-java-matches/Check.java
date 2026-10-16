import java.util.regex.*;

public class Check {
    static boolean valid(String s) {
        return s.matches("[a-z0-9]+");
    }
    static boolean anchored(String s) {
        Matcher m = Pattern.compile("^[a-z0-9]+$").matcher(s);
        return m.find();
    }
}
