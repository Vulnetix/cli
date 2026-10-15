public class Copy {
    public int fill(java.io.InputStream in) throws Exception {
        byte[] buf = new byte[BUF_SIZE];
        byte[] other = new byte[1024];
        in.read(other, 0, other.length);
        return in.read(buf, 0, BUF_SIZE);
    }
}
