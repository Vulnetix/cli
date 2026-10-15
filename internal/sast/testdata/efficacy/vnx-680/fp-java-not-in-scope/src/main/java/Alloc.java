public class Alloc {
    public static byte[] alloc(String s) {
        int n = Integer.parseInt(s);
        return new byte[n * 4];
    }
}
