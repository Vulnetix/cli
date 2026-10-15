import java.io.InputStream;

public class Reader {
    public int fill(InputStream in) throws Exception {
        byte[] header = new byte[512];
~>        return in.read(header, 0, 512);
    }
}
