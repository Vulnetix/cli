package wire;

public final class Port {
    public static int parse(byte[] b) {
~>        int port = (b[0] & 0xff) << 8 + (b[1] & 0xff);
        return port;
    }
}
